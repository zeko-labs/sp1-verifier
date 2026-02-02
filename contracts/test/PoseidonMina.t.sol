// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PoseidonMina} from "../src/PoseidonMina.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    uint64 a;
    uint64 b;
    bytes proof;
    bytes publicValues;
    string result;
    bytes32 vkey;
}

contract PoseidonMinaGroth16Test is Test {
    using stdJson for string;

    address verifier;
    PoseidonMina public poseidonMina;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        poseidonMina = new PoseidonMina(verifier, fixture.vkey);
    }

    function test_ValidPoseidonProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        bytes32 result = poseidonMina.verifyPoseidonProof(fixture.publicValues, fixture.proof);
        
        // Verify the result matches the expected hash from fixture
        bytes32 expectedResult = bytes32(fixture.publicValues);
        assertEq(result, expectedResult);
        
        console.log("a:", fixture.a);
        console.log("b:", fixture.b);
        console.logBytes32(result);
    }

    function test_ValidPoseidonHashVerification() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        bytes32 expectedHash = bytes32(fixture.publicValues);
        bool valid = poseidonMina.verifyPoseidonHash(fixture.publicValues, fixture.proof, expectedHash);
        assertTrue(valid);
    }

    function testRevert_InvalidPoseidonProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.expectRevert();

        // Create a fake proof
        bytes memory fakeProof = new bytes(fixture.proof.length);

        poseidonMina.verifyPoseidonProof(fixture.publicValues, fakeProof);
    }

    function testRevert_InvalidPublicValuesLength() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        vm.expectRevert("Invalid public values length");

        // Create invalid public values (wrong length)
        bytes memory invalidPublicValues = new bytes(16);

        poseidonMina.verifyPoseidonProof(invalidPublicValues, fixture.proof);
    }
}

contract PoseidonMinaPlonkTest is Test {
    using stdJson for string;

    address verifier;
    PoseidonMina public poseidonMina;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        poseidonMina = new PoseidonMina(verifier, fixture.vkey);
    }

    function test_ValidPoseidonProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        bytes32 result = poseidonMina.verifyPoseidonProof(fixture.publicValues, fixture.proof);
        
        // Verify the result matches the expected hash from fixture
        bytes32 expectedResult = bytes32(fixture.publicValues);
        assertEq(result, expectedResult);
        
        console.log("a:", fixture.a);
        console.log("b:", fixture.b);
        console.logBytes32(result);
    }

    function test_ValidPoseidonHashVerification() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        bytes32 expectedHash = bytes32(fixture.publicValues);
        bool valid = poseidonMina.verifyPoseidonHash(fixture.publicValues, fixture.proof, expectedHash);
        assertTrue(valid);
    }

    function testRevert_InvalidPoseidonProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.expectRevert();

        // Create a fake proof
        bytes memory fakeProof = new bytes(fixture.proof.length);

        poseidonMina.verifyPoseidonProof(fixture.publicValues, fakeProof);
    }
}