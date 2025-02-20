core_abi = [
    {
        "name": "ExchangeBalancebleImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::ExchangeBalanceComponent::INewExchangeBalance"
    },
    {
        "name": "core::integer::u256",
        "type": "struct",
        "members": [
            {
                "name": "low",
                "type": "core::integer::u128"
            },
            {
                "name": "high",
                "type": "core::integer::u128"
            }
        ]
    },
    {
        "name": "core::array::Span::<core::starknet::contract_address::ContractAddress>",
        "type": "struct",
        "members": [
            {
                "name": "snapshot",
                "type": "@core::array::Array::<core::starknet::contract_address::ContractAddress>"
            }
        ]
    },
    {
        "name": "kurosawa_akira::ExchangeBalanceComponent::INewExchangeBalance",
        "type": "interface",
        "items": [
            {
                "name": "total_supply",
                "type": "function",
                "inputs": [
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::integer::u256"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "balanceOf",
                "type": "function",
                "inputs": [
                    {
                        "name": "address",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::integer::u256"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "balancesOf",
                "type": "function",
                "inputs": [
                    {
                        "name": "addresses",
                        "type": "core::array::Span::<core::starknet::contract_address::ContractAddress>"
                    },
                    {
                        "name": "tokens",
                        "type": "core::array::Span::<core::starknet::contract_address::ContractAddress>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<core::array::Array::<core::integer::u256>>"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_wrapped_native_token",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_fee_recipient",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "DepositableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::DepositComponent::IDeposit"
    },
    {
        "name": "kurosawa_akira::DepositComponent::IDeposit",
        "type": "interface",
        "items": [
            {
                "name": "deposit",
                "type": "function",
                "inputs": [
                    {
                        "name": "receiver",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "amount",
                        "type": "core::integer::u256"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "deposit_s",
                "type": "function",
                "inputs": [
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "amount",
                        "type": "core::integer::u256"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            }
        ]
    },
    {
        "name": "SignableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::SignerComponent::ISignerLogic"
    },
    {
        "name": "core::array::Span::<core::felt252>",
        "type": "struct",
        "members": [
            {
                "name": "snapshot",
                "type": "@core::array::Array::<core::felt252>"
            }
        ]
    },
    {
        "name": "core::bool",
        "type": "enum",
        "variants": [
            {
                "name": "False",
                "type": "()"
            },
            {
                "name": "True",
                "type": "()"
            }
        ]
    },
    {
        "name": "kurosawa_akira::SignerComponent::ISignerLogic",
        "type": "interface",
        "items": [
            {
                "name": "bind_to_signer",
                "type": "function",
                "inputs": [
                    {
                        "name": "signer",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "set_till_time_approved_scheme",
                "type": "function",
                "inputs": [
                    {
                        "name": "client",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "sign_scheme",
                        "type": "core::felt252"
                    },
                    {
                        "name": "expire_at",
                        "type": "core::integer::u32"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "get_till_time_approved_scheme",
                "type": "function",
                "inputs": [
                    {
                        "name": "client",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "sign_scheme",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::integer::u32"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "check_sign",
                "type": "function",
                "inputs": [
                    {
                        "name": "trader",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "message",
                        "type": "core::felt252"
                    },
                    {
                        "name": "signature",
                        "type": "core::array::Span::<core::felt252>"
                    },
                    {
                        "name": "sign_scheme",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_signer",
                "type": "function",
                "inputs": [
                    {
                        "name": "trader",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_signers",
                "type": "function",
                "inputs": [
                    {
                        "name": "traders",
                        "type": "core::array::Span::<core::starknet::contract_address::ContractAddress>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<core::starknet::contract_address::ContractAddress>"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_verifier_address",
                "type": "function",
                "inputs": [
                    {
                        "name": "sign_scheme",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "WithdrawableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::WithdrawComponent::IWithdraw"
    },
    {
        "name": "kurosawa_akira::Order::GasFee",
        "type": "struct",
        "members": [
            {
                "name": "gas_per_action",
                "type": "core::integer::u32"
            },
            {
                "name": "fee_token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "max_gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "conversion_rate",
                "type": "(core::integer::u256, core::integer::u256)"
            }
        ]
    },
    {
        "name": "kurosawa_akira::WithdrawComponent::Withdraw",
        "type": "struct",
        "members": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            },
            {
                "name": "receiver",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "name": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay",
        "type": "struct",
        "members": [
            {
                "name": "block",
                "type": "core::integer::u64"
            },
            {
                "name": "ts",
                "type": "core::integer::u64"
            }
        ]
    },
    {
        "name": "kurosawa_akira::WithdrawComponent::IWithdraw",
        "type": "interface",
        "items": [
            {
                "name": "request_onchain_withdraw",
                "type": "function",
                "inputs": [
                    {
                        "name": "withdraw",
                        "type": "kurosawa_akira::WithdrawComponent::Withdraw"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "get_pending_withdraw",
                "type": "function",
                "inputs": [
                    {
                        "name": "maker",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "(kurosawa_akira::utils::SlowModeLogic::SlowModeDelay, kurosawa_akira::WithdrawComponent::Withdraw)"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_pending_withdraws",
                "type": "function",
                "inputs": [
                    {
                        "name": "reqs",
                        "type": "core::array::Array::<(core::starknet::contract_address::ContractAddress, core::starknet::contract_address::ContractAddress)>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<(kurosawa_akira::utils::SlowModeLogic::SlowModeDelay, kurosawa_akira::WithdrawComponent::Withdraw)>"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "apply_onchain_withdraw",
                "type": "function",
                "inputs": [
                    {
                        "name": "token",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "key",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "get_withdraw_steps",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::integer::u32"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "is_request_completed",
                "type": "function",
                "inputs": [
                    {
                        "name": "w_hash",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "is_requests_completed",
                "type": "function",
                "inputs": [
                    {
                        "name": "reqs",
                        "type": "core::array::Array::<core::felt252>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<core::bool>"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "NonceableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::NonceComponent::INonceLogic"
    },
    {
        "name": "kurosawa_akira::NonceComponent::INonceLogic",
        "type": "interface",
        "items": [
            {
                "name": "get_nonce",
                "type": "function",
                "inputs": [
                    {
                        "name": "maker",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::integer::u32"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_nonces",
                "type": "function",
                "inputs": [
                    {
                        "name": "makers",
                        "type": "core::array::Span::<core::starknet::contract_address::ContractAddress>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<core::integer::u32>"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "AccsesorableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::AccessorComponent::IAccesorableImpl"
    },
    {
        "name": "kurosawa_akira::AccessorComponent::IAccesorableImpl",
        "type": "interface",
        "items": [
            {
                "name": "get_approved_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "user",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "(core::starknet::contract_address::ContractAddress, core::integer::u16)"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "is_approved_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "user",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_owner",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_executor",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "(core::starknet::contract_address::ContractAddress, core::integer::u16)"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "set_owner",
                "type": "function",
                "inputs": [
                    {
                        "name": "new_owner",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "set_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "new_executor",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "grant_access_to_executor",
                "type": "function",
                "inputs": [],
                "outputs": [],
                "state_mutability": "external"
            }
        ]
    },
    {
        "name": "constructor",
        "type": "constructor",
        "inputs": [
            {
                "name": "wrapped_native_token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "max_slow_mode_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            },
            {
                "name": "withdraw_action_cost",
                "type": "core::integer::u32"
            },
            {
                "name": "owner",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "name": "get_withdraw_delay_params",
        "type": "function",
        "inputs": [],
        "outputs": [
            {
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            }
        ],
        "state_mutability": "view"
    },
    {
        "name": "get_max_delay_params",
        "type": "function",
        "inputs": [],
        "outputs": [
            {
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            }
        ],
        "state_mutability": "view"
    },
    {
        "name": "get_withdraw_hash",
        "type": "function",
        "inputs": [
            {
                "name": "withdraw",
                "type": "kurosawa_akira::WithdrawComponent::Withdraw"
            }
        ],
        "outputs": [
            {
                "type": "core::felt252"
            }
        ],
        "state_mutability": "view"
    },
    {
        "name": "kurosawa_akira::NonceComponent::IncreaseNonce",
        "type": "struct",
        "members": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "new_nonce",
                "type": "core::integer::u32"
            },
            {
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            },
            {
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "name": "get_increase_nonce_hash",
        "type": "function",
        "inputs": [
            {
                "name": "increase_nonce",
                "type": "kurosawa_akira::NonceComponent::IncreaseNonce"
            }
        ],
        "outputs": [
            {
                "type": "core::felt252"
            }
        ],
        "state_mutability": "view"
    },
    {
        "name": "add_signer_scheme",
        "type": "function",
        "inputs": [
            {
                "name": "verifier_address",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "transfer",
        "type": "function",
        "inputs": [
            {
                "name": "from",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "to",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "safe_mint",
        "type": "function",
        "inputs": [
            {
                "name": "to",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "safe_burn",
        "type": "function",
        "inputs": [
            {
                "name": "to",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [
            {
                "type": "core::integer::u256"
            }
        ],
        "state_mutability": "external"
    },
    {
        "name": "rebalance_after_trade",
        "type": "function",
        "inputs": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "taker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "ticker",
                "type": "(core::starknet::contract_address::ContractAddress, core::starknet::contract_address::ContractAddress)"
            },
            {
                "name": "amount_base",
                "type": "core::integer::u256"
            },
            {
                "name": "amount_quote",
                "type": "core::integer::u256"
            },
            {
                "name": "is_maker_seller",
                "type": "core::bool"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_withdraw_component_params",
        "type": "function",
        "inputs": [
            {
                "name": "new_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_fee_recipient",
        "type": "function",
        "inputs": [
            {
                "name": "new_fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_base_token",
        "type": "function",
        "inputs": [
            {
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::NonceComponent::SignedIncreaseNonce",
        "type": "struct",
        "members": [
            {
                "name": "increase_nonce",
                "type": "kurosawa_akira::NonceComponent::IncreaseNonce"
            },
            {
                "name": "sign",
                "type": "core::array::Span::<core::felt252>"
            }
        ]
    },
    {
        "name": "apply_increase_nonce",
        "type": "function",
        "inputs": [
            {
                "name": "signed_nonce",
                "type": "kurosawa_akira::NonceComponent::SignedIncreaseNonce"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "apply_increase_nonces",
        "type": "function",
        "inputs": [
            {
                "name": "signed_nonces",
                "type": "core::array::Array::<kurosawa_akira::NonceComponent::SignedIncreaseNonce>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::WithdrawComponent::SignedWithdraw",
        "type": "struct",
        "members": [
            {
                "name": "withdraw",
                "type": "kurosawa_akira::WithdrawComponent::Withdraw"
            },
            {
                "name": "sign",
                "type": "core::array::Span::<core::felt252>"
            }
        ]
    },
    {
        "name": "apply_withdraw",
        "type": "function",
        "inputs": [
            {
                "name": "signed_withdraw",
                "type": "kurosawa_akira::WithdrawComponent::SignedWithdraw"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "apply_withdraws",
        "type": "function",
        "inputs": [
            {
                "name": "signed_withdraws",
                "type": "core::array::Array::<kurosawa_akira::WithdrawComponent::SignedWithdraw>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Mint",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "to",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Transfer",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "from_",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "to",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Burn",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "from_",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::FeeReward",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Punish",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "taker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "maker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Trade",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "taker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "ticker",
                "type": "(core::starknet::contract_address::ContractAddress, core::starknet::contract_address::ContractAddress)"
            },
            {
                "kind": "data",
                "name": "router_maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "router_taker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount_base",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "amount_quote",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "is_sell_side",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "is_failed",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "is_ecosystem_book",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "maker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "taker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "maker_source",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "taker_source",
                "type": "core::felt252"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "Mint",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Mint"
            },
            {
                "kind": "nested",
                "name": "Transfer",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Transfer"
            },
            {
                "kind": "nested",
                "name": "Burn",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Burn"
            },
            {
                "kind": "nested",
                "name": "FeeReward",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::FeeReward"
            },
            {
                "kind": "nested",
                "name": "Punish",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Punish"
            },
            {
                "kind": "nested",
                "name": "Trade",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Trade"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::DepositComponent::deposit_component::Deposit",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "receiver",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "funder",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::DepositComponent::deposit_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "Deposit",
                "type": "kurosawa_akira::DepositComponent::deposit_component::Deposit"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::SignerComponent::signer_logic_component::NewBinding",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "trading_account",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "signer",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::SignerComponent::signer_logic_component::NewSignScheme",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "verifier_address",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::SignerComponent::signer_logic_component::ApprovalSignScheme",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "trading_account",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "sign_scheme",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "expire_at",
                "type": "core::integer::u32"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::SignerComponent::signer_logic_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "NewBinding",
                "type": "kurosawa_akira::SignerComponent::signer_logic_component::NewBinding"
            },
            {
                "kind": "nested",
                "name": "NewSignScheme",
                "type": "kurosawa_akira::SignerComponent::signer_logic_component::NewSignScheme"
            },
            {
                "kind": "nested",
                "name": "ApprovalSignScheme",
                "type": "kurosawa_akira::SignerComponent::signer_logic_component::ApprovalSignScheme"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::WithdrawComponent::withdraw_component::ReqOnChainWithdraw",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "withdraw",
                "type": "kurosawa_akira::WithdrawComponent::Withdraw"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::WithdrawComponent::withdraw_component::Withdrawal",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "receiver",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            },
            {
                "kind": "data",
                "name": "direct",
                "type": "core::bool"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::WithdrawComponent::withdraw_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "ReqOnChainWithdraw",
                "type": "kurosawa_akira::WithdrawComponent::withdraw_component::ReqOnChainWithdraw"
            },
            {
                "kind": "nested",
                "name": "Withdrawal",
                "type": "kurosawa_akira::WithdrawComponent::withdraw_component::Withdrawal"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::OwnerChanged",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_owner",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::ExecutorChanged",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_executor",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "new_epoch",
                "type": "core::integer::u16"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::ApprovalGranted",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "user",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "executor",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "epoch",
                "type": "core::integer::u16"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "OwnerChanged",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::OwnerChanged"
            },
            {
                "kind": "nested",
                "name": "ExecutorChanged",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::ExecutorChanged"
            },
            {
                "kind": "nested",
                "name": "ApprovalGranted",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::ApprovalGranted"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::NonceComponent::nonce_component::NonceIncrease",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "new_nonce",
                "type": "core::integer::u32"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::NonceComponent::nonce_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "NonceIncrease",
                "type": "kurosawa_akira::NonceComponent::nonce_component::NonceIncrease"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::BaseTokenUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::FeeRecipientUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::WithdrawComponentUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "BalancerEvent",
                "type": "kurosawa_akira::ExchangeBalanceComponent::exchange_balance_logic_component::Event"
            },
            {
                "kind": "nested",
                "name": "DepositEvent",
                "type": "kurosawa_akira::DepositComponent::deposit_component::Event"
            },
            {
                "kind": "nested",
                "name": "SignerEvent",
                "type": "kurosawa_akira::SignerComponent::signer_logic_component::Event"
            },
            {
                "kind": "nested",
                "name": "WithdrawEvent",
                "type": "kurosawa_akira::WithdrawComponent::withdraw_component::Event"
            },
            {
                "kind": "nested",
                "name": "AccessorEvent",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::Event"
            },
            {
                "kind": "nested",
                "name": "NonceEvent",
                "type": "kurosawa_akira::NonceComponent::nonce_component::Event"
            },
            {
                "kind": "nested",
                "name": "BaseTokenUpdate",
                "type": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::BaseTokenUpdate"
            },
            {
                "kind": "nested",
                "name": "FeeRecipientUpdate",
                "type": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::FeeRecipientUpdate"
            },
            {
                "kind": "nested",
                "name": "WithdrawComponentUpdate",
                "type": "kurosawa_akira::LayerAkiraCore::LayerAkiraCore::WithdrawComponentUpdate"
            }
        ]
    }
]

router_abi = [
    {
        "name": "RoutableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::RouterComponent::IRouter"
    },
    {
        "name": "core::integer::u256",
        "type": "struct",
        "members": [
            {
                "name": "low",
                "type": "core::integer::u128"
            },
            {
                "name": "high",
                "type": "core::integer::u128"
            }
        ]
    },
    {
        "name": "core::bool",
        "type": "enum",
        "variants": [
            {
                "name": "False",
                "type": "()"
            },
            {
                "name": "True",
                "type": "()"
            }
        ]
    },
    {
        "name": "kurosawa_akira::RouterComponent::IRouter",
        "type": "interface",
        "items": [
            {
                "name": "get_base_token",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "router_deposit",
                "type": "function",
                "inputs": [
                    {
                        "name": "router",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "coin",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "amount",
                        "type": "core::integer::u256"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "router_withdraw",
                "type": "function",
                "inputs": [
                    {
                        "name": "coin",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "amount",
                        "type": "core::integer::u256"
                    },
                    {
                        "name": "receiver",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "register_router",
                "type": "function",
                "inputs": [],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "add_router_binding",
                "type": "function",
                "inputs": [
                    {
                        "name": "signer",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "request_onchain_deregister",
                "type": "function",
                "inputs": [],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "apply_onchain_deregister",
                "type": "function",
                "inputs": [],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "validate_router",
                "type": "function",
                "inputs": [
                    {
                        "name": "message",
                        "type": "core::felt252"
                    },
                    {
                        "name": "signature",
                        "type": "(core::felt252, core::felt252)"
                    },
                    {
                        "name": "signer",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "router",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_punishment_factor_bips",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::integer::u16"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "is_registered",
                "type": "function",
                "inputs": [
                    {
                        "name": "router",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "have_sufficient_amount_to_route",
                "type": "function",
                "inputs": [
                    {
                        "name": "router",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "balance_of_router",
                "type": "function",
                "inputs": [
                    {
                        "name": "router",
                        "type": "core::starknet::contract_address::ContractAddress"
                    },
                    {
                        "name": "coin",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::integer::u256"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_router",
                "type": "function",
                "inputs": [
                    {
                        "name": "signer",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_route_amount",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::integer::u256"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "AccsesorableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::AccessorComponent::IAccesorableImpl"
    },
    {
        "name": "kurosawa_akira::AccessorComponent::IAccesorableImpl",
        "type": "interface",
        "items": [
            {
                "name": "get_approved_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "user",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "(core::starknet::contract_address::ContractAddress, core::integer::u16)"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "is_approved_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "user",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::bool"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_owner",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_executor",
                "type": "function",
                "inputs": [],
                "outputs": [
                    {
                        "type": "(core::starknet::contract_address::ContractAddress, core::integer::u16)"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "set_owner",
                "type": "function",
                "inputs": [
                    {
                        "name": "new_owner",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "set_executor",
                "type": "function",
                "inputs": [
                    {
                        "name": "new_executor",
                        "type": "core::starknet::contract_address::ContractAddress"
                    }
                ],
                "outputs": [],
                "state_mutability": "external"
            },
            {
                "name": "grant_access_to_executor",
                "type": "function",
                "inputs": [],
                "outputs": [],
                "state_mutability": "external"
            }
        ]
    },
    {
        "name": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay",
        "type": "struct",
        "members": [
            {
                "name": "block",
                "type": "core::integer::u64"
            },
            {
                "name": "ts",
                "type": "core::integer::u64"
            }
        ]
    },
    {
        "name": "constructor",
        "type": "constructor",
        "inputs": [
            {
                "name": "wrapped_native_token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "max_slow_mode_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            },
            {
                "name": "min_to_route",
                "type": "core::integer::u256"
            },
            {
                "name": "owner",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "core_address",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "name": "update_base_token",
        "type": "function",
        "inputs": [
            {
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_router_component_params",
        "type": "function",
        "inputs": [
            {
                "name": "new_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            },
            {
                "name": "min_amount_to_route",
                "type": "core::integer::u256"
            },
            {
                "name": "new_punishment_bips",
                "type": "core::integer::u16"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "transfer_to_core",
        "type": "function",
        "inputs": [
            {
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            }
        ],
        "outputs": [
            {
                "type": "core::integer::u256"
            }
        ],
        "state_mutability": "external"
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::Deposit",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "funder",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::Withdraw",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "receiver",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::RouterRegistration",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "status",
                "type": "core::integer::u8"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::Binding",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "signer",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "is_added",
                "type": "core::bool"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::RouterMint",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::RouterComponent::router_component::RouterBurn",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::RouterComponent::router_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "Deposit",
                "type": "kurosawa_akira::RouterComponent::router_component::Deposit"
            },
            {
                "kind": "nested",
                "name": "Withdraw",
                "type": "kurosawa_akira::RouterComponent::router_component::Withdraw"
            },
            {
                "kind": "nested",
                "name": "RouterRegistration",
                "type": "kurosawa_akira::RouterComponent::router_component::RouterRegistration"
            },
            {
                "kind": "nested",
                "name": "Binding",
                "type": "kurosawa_akira::RouterComponent::router_component::Binding"
            },
            {
                "kind": "nested",
                "name": "RouterMint",
                "type": "kurosawa_akira::RouterComponent::router_component::RouterMint"
            },
            {
                "kind": "nested",
                "name": "RouterBurn",
                "type": "kurosawa_akira::RouterComponent::router_component::RouterBurn"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::UpdateExchangeInvoker",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "invoker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "enabled",
                "type": "core::bool"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::BaseTokenUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::RouterComponentUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_delay",
                "type": "kurosawa_akira::utils::SlowModeLogic::SlowModeDelay"
            },
            {
                "kind": "data",
                "name": "min_amount_to_route",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "new_punishment_bips",
                "type": "core::integer::u16"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::OwnerChanged",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_owner",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::ExecutorChanged",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_executor",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "new_epoch",
                "type": "core::integer::u16"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::ApprovalGranted",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "user",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "executor",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "epoch",
                "type": "core::integer::u16"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::AccessorComponent::accessor_logic_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "OwnerChanged",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::OwnerChanged"
            },
            {
                "kind": "nested",
                "name": "ExecutorChanged",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::ExecutorChanged"
            },
            {
                "kind": "nested",
                "name": "ApprovalGranted",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::ApprovalGranted"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "RouterEvent",
                "type": "kurosawa_akira::RouterComponent::router_component::Event"
            },
            {
                "kind": "nested",
                "name": "UpdateExchangeInvoker",
                "type": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::UpdateExchangeInvoker"
            },
            {
                "kind": "nested",
                "name": "BaseTokenUpdate",
                "type": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::BaseTokenUpdate"
            },
            {
                "kind": "nested",
                "name": "RouterComponentUpdate",
                "type": "kurosawa_akira::LayerAkiraExternalGrantor::LayerAkiraExternalGrantor::RouterComponentUpdate"
            },
            {
                "kind": "nested",
                "name": "AccessorEvent",
                "type": "kurosawa_akira::AccessorComponent::accessor_logic_component::Event"
            }
        ]
    }
]
executor_abi = [
    {
        "name": "BaseOrderTradableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::BaseTradeComponent::IBaseOrderTradeLogic"
    },
    {
        "name": "core::integer::u256",
        "type": "struct",
        "members": [
            {
                "name": "low",
                "type": "core::integer::u128"
            },
            {
                "name": "high",
                "type": "core::integer::u128"
            }
        ]
    },
    {
        "name": "core::bool",
        "type": "enum",
        "variants": [
            {
                "name": "False",
                "type": "()"
            },
            {
                "name": "True",
                "type": "()"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::OrderTradeInfo",
        "type": "struct",
        "members": [
            {
                "name": "filled_base_amount",
                "type": "core::integer::u256"
            },
            {
                "name": "filled_quote_amount",
                "type": "core::integer::u256"
            },
            {
                "name": "last_traded_px",
                "type": "core::integer::u256"
            },
            {
                "name": "num_trades_happened",
                "type": "core::integer::u16"
            },
            {
                "name": "as_taker_completed",
                "type": "core::bool"
            }
        ]
    },
    {
        "name": "kurosawa_akira::BaseTradeComponent::IBaseOrderTradeLogic",
        "type": "interface",
        "items": [
            {
                "name": "get_ecosystem_trade_info",
                "type": "function",
                "inputs": [
                    {
                        "name": "order_hash",
                        "type": "core::felt252"
                    }
                ],
                "outputs": [
                    {
                        "type": "kurosawa_akira::Order::OrderTradeInfo"
                    }
                ],
                "state_mutability": "view"
            },
            {
                "name": "get_ecosystem_trades_info",
                "type": "function",
                "inputs": [
                    {
                        "name": "order_hashes",
                        "type": "core::array::Array::<core::felt252>"
                    }
                ],
                "outputs": [
                    {
                        "type": "core::array::Array::<kurosawa_akira::Order::OrderTradeInfo>"
                    }
                ],
                "state_mutability": "view"
            }
        ]
    },
    {
        "name": "SORTradableImpl",
        "type": "impl",
        "interface_name": "kurosawa_akira::SORTradeComponent::ISORTradeLogic"
    },
    {
        "name": "kurosawa_akira::SORTradeComponent::ISORTradeLogic",
        "type": "interface",
        "items": []
    },
    {
        "name": "constructor",
        "type": "constructor",
        "inputs": [
            {
                "name": "core_address",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "router_address",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "owner",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "name": "update_exchange_invokers",
        "type": "function",
        "inputs": [
            {
                "name": "invoker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "enabled",
                "type": "core::bool"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_fee_recipient",
        "type": "function",
        "inputs": [
            {
                "name": "new_fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "update_base_token",
        "type": "function",
        "inputs": [
            {
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::Order::Quantity",
        "type": "struct",
        "members": [
            {
                "name": "base_qty",
                "type": "core::integer::u256"
            },
            {
                "name": "quote_qty",
                "type": "core::integer::u256"
            },
            {
                "name": "base_asset",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::FixedFee",
        "type": "struct",
        "members": [
            {
                "name": "recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "maker_pbips",
                "type": "core::integer::u32"
            },
            {
                "name": "taker_pbips",
                "type": "core::integer::u32"
            },
            {
                "name": "apply_to_receipt_amount",
                "type": "core::bool"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::GasFee",
        "type": "struct",
        "members": [
            {
                "name": "gas_per_action",
                "type": "core::integer::u32"
            },
            {
                "name": "fee_token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "max_gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "conversion_rate",
                "type": "(core::integer::u256, core::integer::u256)"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::OrderFee",
        "type": "struct",
        "members": [
            {
                "name": "trade_fee",
                "type": "kurosawa_akira::Order::FixedFee"
            },
            {
                "name": "router_fee",
                "type": "kurosawa_akira::Order::FixedFee"
            },
            {
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::TakerSelfTradePreventionMode",
        "type": "enum",
        "variants": [
            {
                "name": "NONE",
                "type": "()"
            },
            {
                "name": "EXPIRE_TAKER",
                "type": "()"
            },
            {
                "name": "EXPIRE_MAKER",
                "type": "()"
            },
            {
                "name": "EXPIRE_BOTH",
                "type": "()"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::Constraints",
        "type": "struct",
        "members": [
            {
                "name": "number_of_swaps_allowed",
                "type": "core::integer::u16"
            },
            {
                "name": "duration_valid",
                "type": "core::integer::u32"
            },
            {
                "name": "created_at",
                "type": "core::integer::u32"
            },
            {
                "name": "stp",
                "type": "kurosawa_akira::Order::TakerSelfTradePreventionMode"
            },
            {
                "name": "nonce",
                "type": "core::integer::u32"
            },
            {
                "name": "min_receive_amount",
                "type": "core::integer::u256"
            },
            {
                "name": "router_signer",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::OrderFlags",
        "type": "struct",
        "members": [
            {
                "name": "full_fill_only",
                "type": "core::bool"
            },
            {
                "name": "best_level_only",
                "type": "core::bool"
            },
            {
                "name": "post_only",
                "type": "core::bool"
            },
            {
                "name": "is_sell_side",
                "type": "core::bool"
            },
            {
                "name": "is_market_order",
                "type": "core::bool"
            },
            {
                "name": "to_ecosystem_book",
                "type": "core::bool"
            },
            {
                "name": "external_funds",
                "type": "core::bool"
            }
        ]
    },
    {
        "name": "kurosawa_akira::Order::Order",
        "type": "struct",
        "members": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "price",
                "type": "core::integer::u256"
            },
            {
                "name": "qty",
                "type": "kurosawa_akira::Order::Quantity"
            },
            {
                "name": "ticker",
                "type": "(core::starknet::contract_address::ContractAddress, core::starknet::contract_address::ContractAddress)"
            },
            {
                "name": "fee",
                "type": "kurosawa_akira::Order::OrderFee"
            },
            {
                "name": "constraints",
                "type": "kurosawa_akira::Order::Constraints"
            },
            {
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "name": "flags",
                "type": "kurosawa_akira::Order::OrderFlags"
            },
            {
                "name": "source",
                "type": "core::felt252"
            },
            {
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "name": "get_order_hash",
        "type": "function",
        "inputs": [
            {
                "name": "order",
                "type": "kurosawa_akira::Order::Order"
            }
        ],
        "outputs": [
            {
                "type": "core::felt252"
            }
        ],
        "state_mutability": "view"
    },
    {
        "name": "kurosawa_akira::NonceComponent::IncreaseNonce",
        "type": "struct",
        "members": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "new_nonce",
                "type": "core::integer::u32"
            },
            {
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            },
            {
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "name": "core::array::Span::<core::felt252>",
        "type": "struct",
        "members": [
            {
                "name": "snapshot",
                "type": "@core::array::Array::<core::felt252>"
            }
        ]
    },
    {
        "name": "kurosawa_akira::NonceComponent::SignedIncreaseNonce",
        "type": "struct",
        "members": [
            {
                "name": "increase_nonce",
                "type": "kurosawa_akira::NonceComponent::IncreaseNonce"
            },
            {
                "name": "sign",
                "type": "core::array::Span::<core::felt252>"
            }
        ]
    },
    {
        "name": "apply_increase_nonce",
        "type": "function",
        "inputs": [
            {
                "name": "signed_nonce",
                "type": "kurosawa_akira::NonceComponent::SignedIncreaseNonce"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "apply_increase_nonces",
        "type": "function",
        "inputs": [
            {
                "name": "signed_nonces",
                "type": "core::array::Array::<kurosawa_akira::NonceComponent::SignedIncreaseNonce>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::WithdrawComponent::Withdraw",
        "type": "struct",
        "members": [
            {
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "amount",
                "type": "core::integer::u256"
            },
            {
                "name": "salt",
                "type": "core::felt252"
            },
            {
                "name": "gas_fee",
                "type": "kurosawa_akira::Order::GasFee"
            },
            {
                "name": "receiver",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "name": "sign_scheme",
                "type": "core::felt252"
            }
        ]
    },
    {
        "name": "kurosawa_akira::WithdrawComponent::SignedWithdraw",
        "type": "struct",
        "members": [
            {
                "name": "withdraw",
                "type": "kurosawa_akira::WithdrawComponent::Withdraw"
            },
            {
                "name": "sign",
                "type": "core::array::Span::<core::felt252>"
            }
        ]
    },
    {
        "name": "apply_withdraw",
        "type": "function",
        "inputs": [
            {
                "name": "signed_withdraw",
                "type": "kurosawa_akira::WithdrawComponent::SignedWithdraw"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "apply_withdraws",
        "type": "function",
        "inputs": [
            {
                "name": "signed_withdraws",
                "type": "core::array::Array::<kurosawa_akira::WithdrawComponent::SignedWithdraw>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::Order::SignedOrder",
        "type": "struct",
        "members": [
            {
                "name": "order",
                "type": "kurosawa_akira::Order::Order"
            },
            {
                "name": "sign",
                "type": "core::array::Span::<core::felt252>"
            },
            {
                "name": "router_sign",
                "type": "(core::felt252, core::felt252)"
            }
        ]
    },
    {
        "name": "apply_ecosystem_trades",
        "type": "function",
        "inputs": [
            {
                "name": "taker_orders",
                "type": "core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::bool)>"
            },
            {
                "name": "maker_orders",
                "type": "core::array::Array::<kurosawa_akira::Order::SignedOrder>"
            },
            {
                "name": "iters",
                "type": "core::array::Array::<(core::integer::u16, core::bool)>"
            },
            {
                "name": "oracle_settled_qty",
                "type": "core::array::Array::<core::integer::u256>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "apply_single_execution_step",
        "type": "function",
        "inputs": [
            {
                "name": "taker_order",
                "type": "kurosawa_akira::Order::SignedOrder"
            },
            {
                "name": "maker_orders",
                "type": "core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::integer::u256)>"
            },
            {
                "name": "total_amount_matched",
                "type": "core::integer::u256"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            },
            {
                "name": "as_taker_completed",
                "type": "core::bool"
            }
        ],
        "outputs": [
            {
                "type": "core::bool"
            }
        ],
        "state_mutability": "external"
    },
    {
        "name": "apply_execution_steps",
        "type": "function",
        "inputs": [
            {
                "name": "bulk",
                "type": "core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::integer::u256)>, core::integer::u256, core::bool)>"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            },
            {
                "name": "cur_gas_per_action",
                "type": "core::integer::u32"
            }
        ],
        "outputs": [
            {
                "type": "core::array::Array::<core::bool>"
            }
        ],
        "state_mutability": "external"
    },
    {
        "name": "placeTakerOrder",
        "type": "function",
        "inputs": [
            {
                "name": "order",
                "type": "kurosawa_akira::Order::Order"
            },
            {
                "name": "router_sign",
                "type": "(core::felt252, core::felt252)"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "fullfillTakerOrder",
        "type": "function",
        "inputs": [
            {
                "name": "maker_orders",
                "type": "core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::integer::u256)>"
            },
            {
                "name": "total_amount_matched",
                "type": "core::integer::u256"
            },
            {
                "name": "gas_steps",
                "type": "core::integer::u32"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "name": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::Step",
        "type": "enum",
        "variants": [
            {
                "name": "BulkExecutionSteps",
                "type": "(core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::integer::u256)>, core::integer::u256, core::bool)>, core::bool)"
            },
            {
                "name": "SingleExecutionStep",
                "type": "((kurosawa_akira::Order::SignedOrder, core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::integer::u256)>, core::integer::u256, core::bool), core::bool)"
            },
            {
                "name": "EcosystemTrades",
                "type": "(core::array::Array::<(kurosawa_akira::Order::SignedOrder, core::bool)>, core::array::Array::<kurosawa_akira::Order::SignedOrder>, core::array::Array::<(core::integer::u16, core::bool)>, core::array::Array::<core::integer::u256>)"
            },
            {
                "name": "IncreaseNonceStep",
                "type": "kurosawa_akira::NonceComponent::SignedIncreaseNonce"
            },
            {
                "name": "WithdrawStep",
                "type": "kurosawa_akira::WithdrawComponent::SignedWithdraw"
            }
        ]
    },
    {
        "name": "apply_steps",
        "type": "function",
        "inputs": [
            {
                "name": "steps",
                "type": "core::array::Array::<kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::Step>"
            },
            {
                "name": "nonce_steps",
                "type": "core::integer::u32"
            },
            {
                "name": "withdraw_steps",
                "type": "core::integer::u32"
            },
            {
                "name": "router_steps",
                "type": "core::integer::u32"
            },
            {
                "name": "ecosystem_steps",
                "type": "core::integer::u32"
            },
            {
                "name": "gas_price",
                "type": "core::integer::u256"
            }
        ],
        "outputs": [],
        "state_mutability": "external"
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::BaseTradeComponent::base_trade_component::FeeReward",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "token",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::BaseTradeComponent::base_trade_component::Punish",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "router",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "taker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "maker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "amount",
                "type": "core::integer::u256"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::BaseTradeComponent::base_trade_component::Trade",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "key",
                "name": "taker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "ticker",
                "type": "(core::starknet::contract_address::ContractAddress, core::starknet::contract_address::ContractAddress)"
            },
            {
                "kind": "data",
                "name": "router_maker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "router_taker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "amount_base",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "amount_quote",
                "type": "core::integer::u256"
            },
            {
                "kind": "data",
                "name": "is_sell_side",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "is_failed",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "is_ecosystem_book",
                "type": "core::bool"
            },
            {
                "kind": "data",
                "name": "maker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "taker_hash",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "maker_source",
                "type": "core::felt252"
            },
            {
                "kind": "data",
                "name": "taker_source",
                "type": "core::felt252"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::BaseTradeComponent::base_trade_component::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "FeeReward",
                "type": "kurosawa_akira::BaseTradeComponent::base_trade_component::FeeReward"
            },
            {
                "kind": "nested",
                "name": "Punish",
                "type": "kurosawa_akira::BaseTradeComponent::base_trade_component::Punish"
            },
            {
                "kind": "nested",
                "name": "Trade",
                "type": "kurosawa_akira::BaseTradeComponent::base_trade_component::Trade"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::SORTradeComponent::sor_trade_component::Event",
        "type": "event",
        "variants": []
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::UpdateExchangeInvoker",
        "type": "event",
        "members": [
            {
                "kind": "key",
                "name": "invoker",
                "type": "core::starknet::contract_address::ContractAddress"
            },
            {
                "kind": "data",
                "name": "enabled",
                "type": "core::bool"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::BaseTokenUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_base_token",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "struct",
        "name": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::FeeRecipientUpdate",
        "type": "event",
        "members": [
            {
                "kind": "data",
                "name": "new_fee_recipient",
                "type": "core::starknet::contract_address::ContractAddress"
            }
        ]
    },
    {
        "kind": "enum",
        "name": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::Event",
        "type": "event",
        "variants": [
            {
                "kind": "nested",
                "name": "BaseTradeEvent",
                "type": "kurosawa_akira::BaseTradeComponent::base_trade_component::Event"
            },
            {
                "kind": "nested",
                "name": "SORTradeEvent",
                "type": "kurosawa_akira::SORTradeComponent::sor_trade_component::Event"
            },
            {
                "kind": "nested",
                "name": "UpdateExchangeInvoker",
                "type": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::UpdateExchangeInvoker"
            },
            {
                "kind": "nested",
                "name": "BaseTokenUpdate",
                "type": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::BaseTokenUpdate"
            },
            {
                "kind": "nested",
                "name": "FeeRecipientUpdate",
                "type": "kurosawa_akira::LayerAkiraExecutor::LayerAkiraExecutor::FeeRecipientUpdate"
            }
        ]
    }
]
