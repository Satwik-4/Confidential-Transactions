// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x06f6a9234f37b768ed85404cb0e1545ce3f74ab4f6ac123f0195c7ee888dcdee), uint256(0x2547046e40cdb7225efacf433452eee46703bd7b34d615ad0aebfa6a2b8f2e97));
        vk.beta = Pairing.G2Point([uint256(0x17db565cfc86adaaedb90e183bb9de4978f9ac2cc25317899df2b76fcb26b5c3), uint256(0x26932b0217d1919cdccd0509e9ebeb8c2e62eaa646ff3eaee8cb337255198c98)], [uint256(0x28b5996e4439774fae5eedf820a7648c8e4a762ea907c5411ec4a5cbfd104b77), uint256(0x2121442a2453a1d927b4493a42c06528b72908731d39f13a865d54a0803769dc)]);
        vk.gamma = Pairing.G2Point([uint256(0x1e5505a4e704260e7051ad2cc6fd538bbf5020ac66824641af5ee05fb19d78fe), uint256(0x2e2ed78451d277c6b52a9e02f745990123eb529028e637c3acafc23e16cf0e1d)], [uint256(0x2b4cd9bb8751afaf2f6a46e66ae6f59d9233338766646ba9ed2a7509b4a4220f), uint256(0x221ed174c7be03a5c2e1ac3f220c54dba4c5ab20b356bab44eba1d5482d8a792)]);
        vk.delta = Pairing.G2Point([uint256(0x2ca48ba98112207b2034004925f442e2b03426d99b72c22a861e9e7aa66d7ccf), uint256(0x01293639ff81e8a13ccfca65f99d2cf1d8c211f05c8b2092d971b5b0dbb520c4)], [uint256(0x15ae9a012ee94d8d19170faa2973336c8a32e978919b114c1c416117ccbc2c24), uint256(0x073f7bded8ec941d931e559d46e32064befd8506274f491dc33f09a4ad27dc68)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x07834ceb6ae05574a2e81ba48669cec245b20310bf971330007ff321377fd27a), uint256(0x28debdeadc1f38e58516baefba67a91b60c9f86f2cb49a434de82840cb8cdb7a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x194f7ebfe8a86ae4188e9045fd47f133f93a3a49eea93d7cc57e2d96fc29bea9), uint256(0x02d102a4e456d37365ce5f1a079acb34d7e35cc60fb428a7e293c36e8882d146));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1594faa95ac67b59c1961f3ef62e8fbf9949ffca39a471ddd325633e2a68a313), uint256(0x01d4ac07d85e3e69b4d647147f5b75b0c1513cd778b09b49ec577f31574ed6c1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0f09986445bb2d34e8b8638be962994a615af5b0d07b75561c27d549e7bf2cfa), uint256(0x141a0cdb3adf0cbfbb11d8eda48f458db640ad177f0360b128294b768479f682));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x09cb55c9319ccc4cc148e6f5da8b1015ade818216177798c22af714e8e83a430), uint256(0x1073c9189f271abe6ccb93bd67a934d8eac725371980b01b236571113d5c4696));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2d5aacfd8311b26b8b649d3c879732cecb68aae180f8c5180a50b55455eeb97a), uint256(0x104ce9133e0aa0d6c87490cc6f63deef93119021de69e4e5cc9c6e1d6564ffe2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0ca6e9aaa79dfe30b7431d32b766ddb57ca2fb5cb886376d8708d3ed159ab313), uint256(0x03f384e39cfa0f68a88f7e5cd17641f470163c0729f5725bfbb0e7ccbf73141c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x131074b4d6f338451859165de81ed0e2dc4c6d985bf54940af13b3a258a0010f), uint256(0x1798edd77563f61521ce0aa7c3c77c605c1c646126983a249088424e29270b4c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2ba65d1fc956fa23b052321b437122cef3f0b893cd5b07e40348c410146b52ea), uint256(0x16f3fd9b943b6b559727c3d1404e828a3f50444f4013b307127643646ee00d4f));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}