// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {EthereumZekoBridge} from "../src/EthereumZekoBridge.sol";
import {ZekoAddress, ZekoAddressLib} from "../src/ZekoAddress.sol";

contract MockERC20 {
    string public constant name = "Mock Token";
    string public constant symbol = "MOCK";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");

        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
    }
}

contract EthereumZekoBridgeTest is Test {
    uint256 private constant ZEKO_FIELD_ORDER =
        28948022309329048855892746252171976963363056481941560715954676764349967630337;

    event BridgeDeposit(
        uint64 indexed nonce,
        bytes32 indexed depositLeaf,
        bytes32 indexed newDepositState,
        bytes32 oldDepositState,
        address token,
        address sender,
        ZekoAddress zekoRecipient,
        uint256 amount
    );

    EthereumZekoBridge private bridge;
    MockERC20 private token;

    address private alice = address(0xA11CE);

    function setUp() public {
        bridge = new EthereumZekoBridge(address(this));
        token = new MockERC20();

        bridge.setAllowedToken(address(token), true);
        token.mint(alice, 100 ether);
    }

    function test_DepositUsesZekoAddressRecipient() public {
        uint256 amount = 5 ether;
        ZekoAddress zekoRecipient = ZekoAddressLib.pack(123456789, true);

        bytes32 oldDepositState = bridge.currentDepositState();
        bytes32 expectedLeaf = bridge.computeDepositLeaf({
            token: address(token),
            sender: alice,
            zekoRecipient: zekoRecipient,
            amount: amount,
            nonce: 1
        });
        bytes32 expectedNewDepositState = bridge.computeNextDepositState(
            oldDepositState,
            expectedLeaf
        );

        vm.startPrank(alice);
        token.approve(address(bridge), amount);

        vm.expectEmit(true, true, true, true);
        emit BridgeDeposit({
            nonce: 1,
            depositLeaf: expectedLeaf,
            newDepositState: expectedNewDepositState,
            oldDepositState: oldDepositState,
            token: address(token),
            sender: alice,
            zekoRecipient: zekoRecipient,
            amount: amount
        });

        (uint64 nonce, bytes32 depositLeaf, bytes32 newDepositState) =
            bridge.deposit(address(token), amount, zekoRecipient);
        vm.stopPrank();

        assertEq(nonce, 1);
        assertEq(depositLeaf, expectedLeaf);
        assertEq(newDepositState, expectedNewDepositState);
        assertEq(bridge.currentDepositState(), expectedNewDepositState);
        assertEq(bridge.depositStateByNonce(1), expectedNewDepositState);
        assertEq(token.balanceOf(address(bridge)), amount);
        assertEq(bridge.totalDepositedByToken(address(token)), amount);
    }

    function test_RevertOnInvalidZekoAddress() public {
        ZekoAddress invalid = ZekoAddress.wrap(ZEKO_FIELD_ORDER);

        vm.expectRevert(ZekoAddressLib.InvalidZekoField.selector);
        bridge.computeDepositLeaf({
            token: address(token),
            sender: alice,
            zekoRecipient: invalid,
            amount: 1 ether,
            nonce: 1
        });
    }
}
