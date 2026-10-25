// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {CounterfactualPreimageRescue} from "./CounterfactualRescue.sol";

/**
 * @title RescueableERC20
 * @notice Concrete reference implementation of an ERC-20 / BEP-20 token equipped with
 *         CounterfactualPreimageRescue. Compiles standalone with zero external dependencies.
 */
contract RescueableERC20 is CounterfactualPreimageRescue {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;

    mapping(address account => uint256 balance) private _balances;
    mapping(address owner => mapping(address spender => uint256 allowance)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error InsufficientBalance(address from, uint256 balance, uint256 needed);
    error InsufficientAllowance(address spender, uint256 allowance, uint256 needed);

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            if (currentAllowance < value) {
                revert InsufficientAllowance(msg.sender, currentAllowance, value);
            }
            unchecked {
                allowance[from][msg.sender] = currentAllowance - value;
            }
        }
        _transfer(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) external {
        totalSupply += value;
        unchecked {
            _balances[to] += value;
        }
        emit Transfer(address(0), to, value);
    }

    function _transfer(address from, address to, uint256 value) internal {
        if (to == address(0)) revert InvalidRecipient();
        uint256 fromBalance = _balances[from];
        if (fromBalance < value) {
            revert InsufficientBalance(from, fromBalance, value);
        }
        unchecked {
            _balances[from] = fromBalance - value;
            _balances[to] += value;
        }
        emit Transfer(from, to, value);
    }

    function _getBalance(address account) internal view override returns (uint256) {
        return _balances[account];
    }

    function _rescueTransfer(address from, address to, uint256 amount) internal override {
        _transfer(from, to, amount);
    }
}
