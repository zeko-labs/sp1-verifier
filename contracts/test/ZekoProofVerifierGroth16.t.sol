// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {ZekoProofVerifier} from "../src/ZekoProofVerifier.sol";

import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier as SP1VerifierGroth16} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";

struct SP1ProofFixtureJson {
    string system;
    string graphqlPath;
    string vkPath;
    bool proofValid;
    uint256 zkappCommandBytesLen;
    uint256 zkappStmtBytesLen;
    uint256 deferredValuesBytesLen;
    uint256 verifierIndexBytesLen;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;
}

contract ZekoProofVerifierGroth16Test is Test {
    using stdJson for string;

    uint256 private constant PUBLIC_VALUES_LENGTH = 577;
    uint256 private constant STATE_ARRAY_LENGTH = 8;

    SP1VerifierGateway public gateway;
    ZekoProofVerifier public zeko;
    SP1ProofFixtureJson public fixture;
    ZekoProofVerifier.DecodedPublicValues public decoded;

    address public owner = address(this);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    function loadFixture() public view returns (SP1ProofFixtureJson memory f) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);

        f.system = json.readString(".system");
        f.graphqlPath = json.readString(".graphqlPath");
        f.vkPath = json.readString(".vkPath");
        f.proofValid = json.readBool(".proofValid");
        f.zkappCommandBytesLen = json.readUint(".zkappCommandBytesLen");
        f.zkappStmtBytesLen = json.readUint(".zkappStmtBytesLen");
        f.deferredValuesBytesLen = json.readUint(".deferredValuesBytesLen");
        f.verifierIndexBytesLen = json.readUint(".verifierIndexBytesLen");
        f.vkey = json.readBytes32(".vkey");
        f.publicValues = json.readBytes(".publicValues");
        f.proof = json.readBytes(".proof");
    }

    function setUp() public {
        fixture = loadFixture();
        decoded = _decodePublicValues(fixture.publicValues);

        gateway = new SP1VerifierGateway(address(this));

        SP1VerifierGroth16 groth16Verifier = new SP1VerifierGroth16();
        gateway.addRoute(address(groth16Verifier));

        zeko = new ZekoProofVerifier(
            address(gateway),
            fixture.vkey,
            decoded.vkHash,
            decoded.actionStateBefore,
            decoded.stateBefore[2]
        );
    }

    function test_SetUp() public view {
        assertEq(address(zeko.verifier()), address(gateway));
        assertEq(zeko.programVKey(), fixture.vkey);
        assertEq(zeko.owner(), owner);
        assertEq(zeko.pendingOwner(), address(0));
        assertEq(zeko.vkHash(), decoded.vkHash);
        assertEq(zeko.actionState(), decoded.actionStateBefore);
        assertEq(zeko.currentRoot(), decoded.stateBefore[2]);
    }

    function test_DecodePublicValues() public view {
        ZekoProofVerifier.DecodedPublicValues memory decodedFromContract =
            zeko.getDecodedPublicValues(fixture.publicValues);

        assertEq(decodedFromContract.proofValid, decoded.proofValid);
        assertEq(decodedFromContract.vkHash, decoded.vkHash);
        assertEq(decodedFromContract.actionStateBefore, decoded.actionStateBefore);

        for (uint256 i = 0; i < STATE_ARRAY_LENGTH; i++) {
            assertEq(decodedFromContract.stateBefore[i], decoded.stateBefore[i]);
            assertEq(decodedFromContract.stateAfter[i], decoded.stateAfter[i]);
        }
    }

    function test_ValidGroth16ProofUpdatesRoot() public {
        uint256 gasBefore = gasleft();

        zeko.verifyAndUpdateRoot(fixture.publicValues, fixture.proof);

        uint256 gasUsed = gasBefore - gasleft();

        console2.log("========================================");
        console2.log("=== GROTH16 - verifyAndUpdateRoot ===");
        console2.log("========================================");
        console2.log("proofValid:", decoded.proofValid);
        console2.log("vkHash:");
        console2.logBytes32(decoded.vkHash);
        console2.log("actionStateBefore:");
        console2.logBytes32(decoded.actionStateBefore);
        console2.log("old root / stateBefore[2]:");
        console2.logBytes32(decoded.stateBefore[2]);
        console2.log("new root / stateAfter[2]:");
        console2.logBytes32(decoded.stateAfter[2]);
        console2.log("Gas used:", gasUsed);
        console2.log("========================================");

        assertEq(zeko.currentRoot(), decoded.stateAfter[2]);
    }

    function test_RevertOnInvalidGroth16Proof() public {
        bytes memory fakeProof = new bytes(fixture.proof.length);

        vm.expectRevert();
        zeko.verifyAndUpdateRoot(fixture.publicValues, fakeProof);
    }

    function test_RevertOnInvalidPublicValuesLengthWhenDecoding() public {
        bytes memory invalidPublicValues = new bytes(16);

        vm.expectRevert(
            abi.encodeWithSelector(
                ZekoProofVerifier.InvalidPublicValuesLength.selector,
                PUBLIC_VALUES_LENGTH,
                invalidPublicValues.length
            )
        );

        zeko.getDecodedPublicValues(invalidPublicValues);
    }

    function test_RevertOnInvalidBoolWhenDecoding() public {
        bytes memory invalidPublicValues = fixture.publicValues;
        invalidPublicValues[0] = bytes1(uint8(2));

        vm.expectRevert(
            abi.encodeWithSelector(
                ZekoProofVerifier.InvalidBool.selector,
                uint8(2)
            )
        );

        zeko.getDecodedPublicValues(invalidPublicValues);
    }

    function test_RevertOnInvalidVkHash() public {
        bytes32 badVkHash = keccak256("bad vk hash");

        zeko.setVkHash(badVkHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                ZekoProofVerifier.InvalidVkHash.selector,
                badVkHash,
                decoded.vkHash
            )
        );

        zeko.verifyAndUpdateRoot(fixture.publicValues, fixture.proof);
    }

    function test_RevertOnInvalidActionState() public {
        bytes32 badActionState = keccak256("bad action state");

        zeko.setActionState(badActionState);

        vm.expectRevert(
            abi.encodeWithSelector(
                ZekoProofVerifier.InvalidActionState.selector,
                badActionState,
                decoded.actionStateBefore
            )
        );

        zeko.verifyAndUpdateRoot(fixture.publicValues, fixture.proof);
    }

    function test_RevertOnInvalidCurrentRoot() public {
        bytes32 badRoot = keccak256("bad root");

        ZekoProofVerifier other = new ZekoProofVerifier(
            address(gateway),
            fixture.vkey,
            decoded.vkHash,
            decoded.actionStateBefore,
            badRoot
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ZekoProofVerifier.InvalidCurrentRoot.selector,
                badRoot,
                decoded.stateBefore[2]
            )
        );

        other.verifyAndUpdateRoot(fixture.publicValues, fixture.proof);
    }

    function test_SetVkHashOnlyOwner() public {
        bytes32 newVkHash = keccak256("new vk hash");

        zeko.setVkHash(newVkHash);

        assertEq(zeko.vkHash(), newVkHash);
    }

    function test_RevertSetVkHashWhenNotOwner() public {
        vm.prank(alice);

        vm.expectRevert(ZekoProofVerifier.NotOwner.selector);
        zeko.setVkHash(keccak256("new vk hash"));
    }

    function test_SetActionStateOnlyOwner() public {
        bytes32 newActionState = keccak256("new action state");

        zeko.setActionState(newActionState);

        assertEq(zeko.actionState(), newActionState);
    }

    function test_RevertSetActionStateWhenNotOwner() public {
        vm.prank(alice);

        vm.expectRevert(ZekoProofVerifier.NotOwner.selector);
        zeko.setActionState(keccak256("new action state"));
    }

    function test_TwoStepOwnershipTransfer() public {
        zeko.transferOwnership(alice);

        assertEq(zeko.owner(), owner);
        assertEq(zeko.pendingOwner(), alice);

        vm.prank(alice);
        zeko.acceptOwnership();

        assertEq(zeko.owner(), alice);
        assertEq(zeko.pendingOwner(), address(0));
    }

    function test_RevertTransferOwnershipWhenNotOwner() public {
        vm.prank(alice);

        vm.expectRevert(ZekoProofVerifier.NotOwner.selector);
        zeko.transferOwnership(bob);
    }

    function test_RevertTransferOwnershipToZeroAddress() public {
        vm.expectRevert(ZekoProofVerifier.ZeroAddress.selector);
        zeko.transferOwnership(address(0));
    }

    function test_RevertAcceptOwnershipWhenNotPendingOwner() public {
        zeko.transferOwnership(alice);

        vm.prank(bob);

        vm.expectRevert(ZekoProofVerifier.NotPendingOwner.selector);
        zeko.acceptOwnership();
    }

    function test_CancelOwnershipTransfer() public {
        zeko.transferOwnership(alice);

        assertEq(zeko.pendingOwner(), alice);

        zeko.cancelOwnershipTransfer();

        assertEq(zeko.owner(), owner);
        assertEq(zeko.pendingOwner(), address(0));
    }

    function test_RevertCancelOwnershipTransferWhenNotOwner() public {
        zeko.transferOwnership(alice);

        vm.prank(alice);

        vm.expectRevert(ZekoProofVerifier.NotOwner.selector);
        zeko.cancelOwnershipTransfer();
    }

    function _decodePublicValues(
        bytes memory publicValues
    ) private pure returns (ZekoProofVerifier.DecodedPublicValues memory d) {
        require(publicValues.length == PUBLIC_VALUES_LENGTH, "invalid public values length");

        uint256 cursor = 0;

        uint8 proofValidRaw = uint8(publicValues[cursor]);
        require(proofValidRaw <= 1, "invalid proof valid bool");
        d.proofValid = proofValidRaw == 1;
        cursor += 1;

        d.vkHash = _readBytes32(publicValues, cursor);
        cursor += 32;

        for (uint256 i = 0; i < STATE_ARRAY_LENGTH; i++) {
            d.stateBefore[i] = _readBytes32(publicValues, cursor);
            cursor += 32;
        }

        for (uint256 i = 0; i < STATE_ARRAY_LENGTH; i++) {
            d.stateAfter[i] = _readBytes32(publicValues, cursor);
            cursor += 32;
        }

        d.actionStateBefore = _readBytes32(publicValues, cursor);
        cursor += 32;

        assert(cursor == PUBLIC_VALUES_LENGTH);
    }

    function _readBytes32(
        bytes memory data,
        uint256 offset
    ) private pure returns (bytes32 value) {
        assembly {
            value := mload(add(add(data, 0x20), offset))
        }
    }
}