// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PoseidonMina} from "../src/PoseidonMina.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier as SP1VerifierGroth16} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";
import {SP1Verifier as SP1VerifierPlonk} from "@sp1-contracts/v5.0.0/SP1VerifierPlonk.sol";

struct SP1ProofFixtureJson {
    uint64 a;
    uint64 b;
    bytes proof;
    bytes32 publicValues;
    string result;
    bytes32 vkey;
}

contract PoseidonMinaGroth16Test is Test {
    using stdJson for string;

    SP1VerifierGateway public gateway;
    PoseidonMina public poseidonMina;
    SP1ProofFixtureJson public fixture;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        fixture = loadFixture();

        gateway = new SP1VerifierGateway(address(this));
        SP1VerifierGroth16 verifier = new SP1VerifierGroth16();
        gateway.addRoute(address(verifier));
        poseidonMina = new PoseidonMina(address(gateway), fixture.vkey);
    }

    function test_ValidPoseidonProof() public view {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);

        uint256 gasBefore = gasleft();
        bytes32 result = poseidonMina.verifyPoseidonProof(pubValBytes, fixture.proof);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("========================================");
        console2.log("=== GROTH16 - verifyPoseidonProof ===");
        console2.log("========================================");
        console2.log("a:", uint256(fixture.a));
        console2.log("b:", uint256(fixture.b));
        console2.log("Output:");
        console2.logBytes32(result);
        console2.log("Gas used:", gasUsed);
        console2.log("========================================");

        assertEq(result, fixture.publicValues);
    }

    function test_ValidPoseidonHashVerification() public view {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);

        uint256 gasBefore = gasleft();
        bool valid = poseidonMina.verifyPoseidonHash(
            pubValBytes,
            fixture.proof,
            fixture.publicValues
        );
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("========================================");
        console2.log("=== GROTH16 - verifyPoseidonHash ===");
        console2.log("========================================");
        console2.log("a:", uint256(fixture.a));
        console2.log("b:", uint256(fixture.b));
        console2.log("Expected hash:");
        console2.logBytes32(fixture.publicValues);
        console2.log("Valid:", valid);
        console2.log("Gas used:", gasUsed);
        console2.log("========================================");

        assertTrue(valid);
    }

    function test_RevertOnInvalidProof() public {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);
        bytes memory fakeProof = new bytes(fixture.proof.length);

        vm.expectRevert();
        poseidonMina.verifyPoseidonProof(pubValBytes, fakeProof);
    }

    function test_RevertOnInvalidPublicValuesLength() public {
        bytes memory invalidPublicValues = new bytes(16);

        vm.expectRevert("Invalid public values length");
        poseidonMina.verifyPoseidonProof(invalidPublicValues, fixture.proof);
    }
}

contract PoseidonMinaPlonkTest is Test {
    using stdJson for string;

    SP1VerifierGateway public gateway;
    PoseidonMina public poseidonMina;
    SP1ProofFixtureJson public fixture;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        fixture = loadFixture();

        gateway = new SP1VerifierGateway(address(this));
        SP1VerifierPlonk verifier = new SP1VerifierPlonk();
        gateway.addRoute(address(verifier));
        poseidonMina = new PoseidonMina(address(gateway), fixture.vkey);
    }

    function test_ValidPoseidonProof() public view {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);

        uint256 gasBefore = gasleft();
        bytes32 result = poseidonMina.verifyPoseidonProof(pubValBytes, fixture.proof);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("========================================");
        console2.log("=== PLONK - verifyPoseidonProof ===");
        console2.log("========================================");
        console2.log("a:", uint256(fixture.a));
        console2.log("b:", uint256(fixture.b));
        console2.log("Output:");
        console2.logBytes32(result);
        console2.log("Gas used:", gasUsed);
        console2.log("========================================");

        assertEq(result, fixture.publicValues);
    }

    function test_ValidPoseidonHashVerification() public view {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);

        uint256 gasBefore = gasleft();
        bool valid = poseidonMina.verifyPoseidonHash(
            pubValBytes,
            fixture.proof,
            fixture.publicValues
        );
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("========================================");
        console2.log("=== PLONK - verifyPoseidonHash ===");
        console2.log("========================================");
        console2.log("a:", uint256(fixture.a));
        console2.log("b:", uint256(fixture.b));
        console2.log("Expected hash:");
        console2.logBytes32(fixture.publicValues);
        console2.log("Valid:", valid);
        console2.log("Gas used:", gasUsed);
        console2.log("========================================");

        assertTrue(valid);
    }

    function test_RevertOnInvalidProof() public {
        bytes memory pubValBytes = abi.encodePacked(fixture.publicValues);
        bytes memory fakeProof = new bytes(fixture.proof.length);

        vm.expectRevert();
        poseidonMina.verifyPoseidonProof(pubValBytes, fakeProof);
    }
}