// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            7688067217989994385175370005327028282099909322677106416431281707406319639423,
            7687918639911294339882576580611551419932980906448618049918745820988988940544
    ];
    uint256[2][2] G_2 = [
        [
            19416347238395346053904471628650357632167467651121103308857735341099000261513,
            5629713732619834991072457517931168493887137950096329836236337958194913995208
        ],
        [
            14818564287622708525366599453145027670883513528967113441973036264782225853822,
            1093590203165612172951959974823697879667418028236485001769558240096626734157
        ]
    ];
    uint256[2][2] VK = [
        [
            6641438587248564619757604689753538304135548553720130719783603169789289278626,
            2958842582700393776340418083390288390102133160047395433523620071077844208746
        ],
        [
            829186231878121656179180900384826771003127521258327122608715899820103869814,
            3184476314875140770975155363105701028751154586041125233515858863088780955438
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 5334244287736231424064414447222403035498744854040611247951599872068521018721;
    uint256 constant alphay  = 5826628319659343863904092616738336735748742316357111936967357009472801113719;
    uint256 constant betax1  = 2643786581100012220014631221074225474319355109117794406977988167574048513509;
    uint256 constant betax2  = 12449173059342628094345145371130645560932578806257593873179431093861057831405;
    uint256 constant betay1  = 5747165685684397387799066469924128991138648070579357279855156996269965691722;
    uint256 constant betay2  = 3947814038932369634393261429147425819338672253510282901014522037839551000851;
    uint256 constant gammax1 = 11583031882139105711447424408630403073631700380677290168962253517194968295441;
    uint256 constant gammax2 = 13309169436780168645803647851161604889162128288899679518837348347556000445284;
    uint256 constant gammay1 = 21113401327591874709495221852049244605493192276052496037196391562185838545998;
    uint256 constant gammay2 = 16390563283991684234946851161657157259038062220768997570204416809238460573802;
    uint256 constant deltax1 = 1329537871422545700008648154216551787153916400421979371963379935557581542990;
    uint256 constant deltax2 = 13357884185377325220108098506576177496864739513316142232606680065474200568337;
    uint256 constant deltay1 = 11110282571685995132647603161844878185849706313934146581945082712821210210666;
    uint256 constant deltay2 = 3823772412287581503726114865000821880476361599179471134977865200469746622815;

    
    uint256 constant IC0x = 13252443962932587446172163841160313711161460849129921237054995563308965315349;
    uint256 constant IC0y = 8030307847295312128406676135925399439520866896572796277845010766661997026221;
    
    uint256 constant IC1x = 16826320447075404979196263419114424336440856128304228093401495084778494500020;
    uint256 constant IC1y = 15121055672599693430439691084054223023879115706099110079180484875393770545481;
    
    uint256 constant IC2x = 20088859051323569508029399184769740989958199790802091225605950143803541558148;
    uint256 constant IC2y = 19990106280127218532508807424128872413530014863422586584241153050281160289110;
    
    uint256 constant IC3x = 11646613513573561092254446242704671323952012099129700082373016697813238461600;
    uint256 constant IC3y = 15276521232639732248756779465429400104802252211371310491805109971935711107513;
    
    uint256 constant IC4x = 17367802153222802611579522324074695434486198885946130921337883845540014226263;
    uint256 constant IC4y = 11078227358640749447811423886168367944514009550710845126952166949448500661343;
    
    uint256 constant IC5x = 8691018895483504461541525410741449815544945413174896836301857844627618097078;
    uint256 constant IC5y = 9144508163438738469029096552703461506736983951154227534595987110266960878536;
    
    uint256 constant IC6x = 17890722527990569081164929490657932121575225204414331697378622145223283052347;
    uint256 constant IC6y = 18586542136754438901829938079798628955354385709005428272947992612522804438865;
    
    uint256 constant IC7x = 21550087413249338787320277846921496783787404896233215496917261719731406100890;
    uint256 constant IC7y = 8584951220215677816659102994319209029158368546432114435123101174519122580890;
    
    uint256 constant IC8x = 8457907431574516324669842097198242710242645093291781228173083926415657388965;
    uint256 constant IC8y = 4171850328375852430274291802575489318397885303289051970727814620993884159874;
    
    uint256 constant IC9x = 7336973283688484686795002853650749943405248659845729615052317910069333576692;
    uint256 constant IC9y = 8184205432651602734174235626148584762752887779471458452206918063161998824917;
    
    uint256 constant IC10x = 3715037730005502927051822614609785819422420369930088073276349675503579535435;
    uint256 constant IC10y = 9958865845888413197674031546810630613005439533335755791547690289780514883026;
    
    uint256 constant IC11x = 5947205214135757437255346714438078454512933805486462077045245537547194737015;
    uint256 constant IC11y = 10119650467942645022329157180255705587565113773451832128968726797799620835585;
    
    uint256 constant IC12x = 2230557501614298551393232903981014237298636281096495422330018920298824414937;
    uint256 constant IC12y = 19521227198857229515326719574942367907870616304788544063962941218999177130906;
    
    uint256 constant IC13x = 21791995384002535261475189980885271213344591058213186070234789317393237212334;
    uint256 constant IC13y = 3665719455536470709216221318141116927435729321022723758352671518902390617614;
    
    uint256 constant IC14x = 9879139989517315748796425731966932645684625143456219051321745859950016611296;
    uint256 constant IC14y = 9839289835083972351828829661052805995633653620223696502705533078711136219167;
    
    uint256 constant IC15x = 14469449005094769384427333699067068710260284294454055338899257160700059499003;
    uint256 constant IC15y = 3966177318264668573298200628826459357360631924759948553795178892383275587360;
    
    uint256 constant IC16x = 9466004964094098226805072368640158192277617311199491722346757447598884703389;
    uint256 constant IC16y = 11574872779488641797909748448800487851075918684282809046686939210685603575694;
    
    uint256 constant IC17x = 5668713235163635247956417583843363990293878794692445941870738449660147675486;
    uint256 constant IC17y = 3917119228004274970301105330946965051572806812189156486319542154510746775433;
    
    uint256 constant IC18x = 12275742908619832553405554917150013549688760692170766309240624196136499804670;
    uint256 constant IC18y = 13508336763441273189408924745285738897956746621394959489700232606935950656809;
    
    uint256 constant IC19x = 3807342438493186719498748479306123919242230571152318579880412944199661568922;
    uint256 constant IC19y = 18165907497706794072684050897673682542840397876744702567438177206160363707374;
    
    uint256 constant IC20x = 3037744713078438240893797377851398441122382271366207200225294227952800338274;
    uint256 constant IC20y = 18530861194434296660329176548741883853078788397850639850692925707297787633609;
    
    uint256 constant IC21x = 1857318199345217961951777780298995459378324570893969850997409761810663646582;
    uint256 constant IC21y = 4002136030108970223303718698591116957977560439452722134381516257888413288046;
    
    uint256 constant IC22x = 7496382668039412692245159661966166238416966009865737416554031675550602834123;
    uint256 constant IC22y = 1091029067748163217775239804339220327818352573633986338858726924645960812437;
    
    uint256 constant IC23x = 7263557573690965711625330253361944107011401132338428896330238610916544650595;
    uint256 constant IC23y = 16850125615888341197682419378710056316836392770051839853149080262695155817800;
    
    uint256 constant IC24x = 9518455772775974045000510086592127748466835273042890831212740417248072029991;
    uint256 constant IC24y = 1488783401637062651831988454764810962919795194557327824503575777021157613305;
    
    uint256 constant IC25x = 15077447218345557153092468829822882990051896500234979413565888000263315102947;
    uint256 constant IC25y = 6585519300106879652175716294284678887801044805633703395744572144545103679715;
    
    uint256 constant IC26x = 11371240377678623693183326487219885699730610290645506773530219840561568076693;
    uint256 constant IC26y = 18505584344763238668522213529749356632434393479478396698286887867016991434668;
    
    uint256 constant IC27x = 2522737279441433158588684433024993221779448018862581310051574292980543397677;
    uint256 constant IC27y = 2380184485898624407375881146425730717326343507068730117989310003240530374498;
    
    uint256 constant IC28x = 21058573747707938852989910821965386286872699505579033788020750320791388261910;
    uint256 constant IC28y = 2531663783623898948105036418607784252411915439993452220107167239987353397424;
    
    uint256 constant IC29x = 4497074308584480454079911010854044027988965911189081830875210636326685542232;
    uint256 constant IC29y = 19000880265789157084004615064643935195423737343783031718664809396159258396615;
    
    uint256 constant IC30x = 7789525904543367347263396064485405456433242544894504058791889311188253249672;
    uint256 constant IC30y = 14527782406393663718909971921393328616250761971216930531000952206250757133516;
    
    uint256 constant IC31x = 2227892952090998477094185597309514360739490901243481799519873951064468932403;
    uint256 constant IC31y = 11441710811859191951401447668543437327456793925911797486360258205272166945684;
    
    uint256 constant IC32x = 7467413370942927603022029229548604056018972989087926341977302661055695195864;
    uint256 constant IC32y = 5411459117054194885375670287835485283862451122719298127244514839429427864437;
    
    uint256 constant IC33x = 879260669232904157224389083718606005140040643449855105894304806114190510838;
    uint256 constant IC33y = 13498096999119857599059968559384841686807616010017345855951200253458164386778;
    
    uint256 constant IC34x = 17433322863202056478004708188502515406128651400138155824317008537735621128184;
    uint256 constant IC34y = 5475793759596977937807644096333152225142556707592258472475341085299222862005;
    
    uint256 constant IC35x = 9852629479300545820113290597691794495629929442930374599703788181286324956642;
    uint256 constant IC35y = 4236914986925208470215425596043662776453717797858881860585674251162139369875;
    
    uint256 constant IC36x = 6490325563184658143510341600890010486715689430033346976089692706021162371029;
    uint256 constant IC36y = 19045149355172333275405554343400237765861935538238990262697733369416486054456;
    
    uint256 constant IC37x = 13928321654702235865182821667454669983516182314610540572881257971728344977897;
    uint256 constant IC37y = 18637165539238039740056740538979758931457060971938706808119357579563316693316;
    
    uint256 constant IC38x = 19942218213118531027982837611284082636165990562462366748892259882746990458436;
    uint256 constant IC38y = 15219493387747922485384309910963908642174418560316711997141086747313004703907;
    
    uint256 constant IC39x = 17565316967144906203532378768646281298599026105564941169541630855214520885417;
    uint256 constant IC39y = 5213062008610988984206446733488993814684314186265727528147036812018281567799;
    
    uint256 constant IC40x = 9835407928008018210439834403252530712911228485460692161459042179613201332187;
    uint256 constant IC40y = 15225400600504190651375846381776901747325593673577917871254819250697902086624;
    
    uint256 constant IC41x = 8788990574423499941553058925329075103932414700250052894654340004492918001533;
    uint256 constant IC41y = 12993219996913307195911340066208190673841072769260684261255934973169800524241;
    
    uint256 constant IC42x = 6860879135096012074663799589848485907866183872681757780944751516642728431723;
    uint256 constant IC42y = 12553139364360811596681161930529144904514662456440009895005723161867692738028;
    
    uint256 constant IC43x = 20258164242568513372804074693205403188409342783622783466963817572080136619983;
    uint256 constant IC43y = 18498635934684935783533121707192048675469631703333494416964550542929661694480;
    
    uint256 constant IC44x = 12641950102487426925258247069694680251087305051454762031390691479189532451935;
    uint256 constant IC44y = 1474742149472200124529796238488168032850521321837151273201147080365319011321;
    
    uint256 constant IC45x = 16761063102545628358311239277492723136334646662979711490438230023244654876249;
    uint256 constant IC45y = 7012119946690192815746183137538784959158038893876280412903451679747788847961;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[45] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))
                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))
                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))
                g1_mulAccC(_pVk, IC45x, IC45y, calldataload(add(pubSignals, 1408)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            
            checkField(calldataload(add(_pubSignals, 1376)))
            
            checkField(calldataload(add(_pubSignals, 1408)))
            
            checkField(calldataload(add(_pubSignals, 1440)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[7] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[3] calldata U_i_u_u_i_u_r, // [U_i_u, u_i_u, r]
        uint256[4] calldata U_i_x_u_i_cmW, // [U_i_x[2], u_i_cmW[2]]
        uint256[4] calldata u_i_x_cmT, // [u_i_x[2], cmT[2]]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[45] memory public_inputs; 

        public_inputs[0] = i_z0_zi[0];

        for (uint i = 0; i < 6; i++) {
            public_inputs[1 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.u + r * u_i.u
            uint256 u = rlc(U_i_u_u_i_u_r[0], U_i_u_u_i_u_r[2], U_i_u_u_i_u_r[1]);
            // U_i.x + r * u_i.x
            uint256 x0 = rlc(U_i_x_u_i_cmW[0], U_i_u_u_i_u_r[2], u_i_x_cmT[0]);
            uint256 x1 = rlc(U_i_x_u_i_cmW[1], U_i_u_u_i_u_r[2], u_i_x_cmT[1]);

            public_inputs[7] = u;
            public_inputs[8] = x0;
            public_inputs[9] = x1;
        }

        {
            // U_i.cmE + r * u_i.cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_x_cmT[2], u_i_x_cmT[3]], U_i_u_u_i_u_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[10 + k] = cmE_x_limbs[k];
                    public_inputs[15 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([U_i_x_u_i_cmW[2], U_i_x_u_i_cmW[3]], U_i_u_u_i_u_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);
        
            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[20 + k] = cmW_x_limbs[k];
                    public_inputs[25 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // add challenges
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[32] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[33] = challenge_W_challenge_E_kzg_evals[3];
        
            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(u_i_x_cmT[2]);
            cmT_y_limbs = LimbsDecomposition.decompose(u_i_x_cmT[3]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[30 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[35 + 4 + k] = cmT_y_limbs[k];
            }
        
            // last element of the groth16 proof's public inputs is `r`
            public_inputs[44] = U_i_u_u_i_u_r[2];
            
            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }
}