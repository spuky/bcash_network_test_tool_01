/*
 * Copyright (c) 2012-2018 bitPico
 *
 * This file is part of libCoin.
 *
 * libCoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <coin/address_manager.hpp>
#include <coin/configuration.hpp>
#include <coin/constants.hpp>
#include <coin/logger.hpp>
#include <coin/protocol.hpp>
#include <coin/stack.hpp>
#include <coin/stack_impl.hpp>

using namespace coin;

stack::stack()
    : stack_impl_(0)
{
    // ...
}

void stack::start(const std::map<std::string, std::string> & args)
{
#define BCASH_STRESS_TEST 1

    if (stack_impl_)
    {
        throw std::runtime_error("Stack is already allocated");
    }
    else
    {
        /**
         * Allocate the stack implementation.
         */
        stack_impl_ = new stack_impl(*this);
        
        /**
         * Set the arguments.
         */
        stack_impl_->get_configuration().set_args(args);

        /**
         * Use different bootstrap endpoints for test networks.
         */
        if (constants::test_net == true)
        {
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.bitcoinabc.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.bitprim.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.deadalnix.me", 0)
            );
            
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed-abc.bitcoinforks.org", 0)
            );
            
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("35.156.118.148", protocol::default_tcp_port_testnet)
            );
            
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("104.154.27.106", protocol::default_tcp_port_testnet)
            );
            
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("175.156.143.145", protocol::default_tcp_port_testnet)
            );
#else
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.breadwallet.com", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.bitcoin.petertodd.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("dnsseed.bitcoin.dashjr.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.bluematt.me", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("bitseed.xf2.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("testnet-seed.bitcoin.schildbach.de", 0)
            );
#endif // BCASH_STRESS_TEST
        }
        else
        {
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.bitcoinabc.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed-abc.bitcoinforks.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("btccash-seeder.bitcoinunlimited.info", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.bitprim.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.deadalnix.me", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seeder.criptolayer.ne", 0)
            );
#else
            /**
             * SegWit1x Specific
             */
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.bitcoin.sipa.be", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("dnsseed.bluematt.me", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("dnsseed.bitcoin.dashjr.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.bitcoinstats.com", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("bitseed.xf2.org", 0)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("seed.bitcoin.jonasschnelli.ch", 0)
            );
#endif // BCASH_STRESS_TEST
        }

        /**
         * Start the stack implementation.
         */
        stack_impl_->start();
    }
}

void stack::stop()
{
    if (stack_impl_)
    {
        /**
         * Stop the stack implementation.
         */
        stack_impl_->stop();
        
        /**
         * Deallocate the stack implementation.
         */
        delete stack_impl_, stack_impl_ = 0;
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::connect()
{
    if (stack_impl_)
    {
        stack_impl_->connect();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::disconnect()
{
    if (stack_impl_)
    {
        stack_impl_->disconnect();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::send_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->send_coins(amount, destination, wallet_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::queue_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->queue_coins(amount, destination, wallet_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::send_queued_coins()
{
    if (stack_impl_)
    {
        stack_impl_->send_queued_coins();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::cancel_queued_coins()
{
    if (stack_impl_)
    {
        stack_impl_->cancel_queued_coins();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::start_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->start_mining(mining_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::stop_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->stop_mining(mining_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

bool stack::wallet_exists(const bool & is_client)
{
    return stack_impl::wallet_exists(is_client);
}

void stack::wallet_encrypt(const std::string & passphrase)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_encrypt(passphrase);
    }
}

void stack::wallet_lock()
{
    if (stack_impl_)
    {
        stack_impl_->wallet_lock();
    }
}

void stack::wallet_unlock(const std::string & passphrase)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_unlock(passphrase);
    }
}

void stack::wallet_change_passphrase(
    const std::string & passphrase_old, const std::string & password_new
    )
{
    if (stack_impl_)
    {
        stack_impl_->wallet_change_passphrase(passphrase_old, password_new);
    }
}

bool stack::wallet_is_crypted(const std::uint32_t & wallet_id)
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_is_crypted(wallet_id);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return false;
}

bool stack::wallet_is_locked(const std::uint32_t & wallet_id)
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_is_locked(wallet_id);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return false;
}

std::string stack::wallet_hd_keychain_seed()
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_hd_keychain_seed();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return std::string();
}

void stack::wallet_generate_address(const std::string & label)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_generate_address(label);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::on_error(const std::map<std::string, std::string> & pairs)
{
    log_error("Stack got error, pairs = " << pairs.size() << ".");
}

void stack::rpc_send(const std::string & command_line)
{
    if (stack_impl_)
    {
        stack_impl_->rpc_send(command_line);
    }
}

void stack::rescan_chain(const std::int64_t & time_from)
{
    if (stack_impl_)
    {
        stack_impl_->rescan_chain(time_from);
    }
}

void stack::ban_ip_address(
    const std::string & ip_or_endpoint, const std::uint32_t & duration
    )
{
    if (stack_impl_)
    {
        stack_impl_->ban_ip_address(ip_or_endpoint, duration);
    }
}

void stack::set_configuration_wallet_transaction_history_maximum(
    const std::time_t & val
    )
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_wallet_transaction_history_maximum(val);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

const std::time_t
    stack::configuration_wallet_transaction_history_maximum() const
{
    if (stack_impl_)
    {
        return stack_impl_->configuration_wallet_transaction_history_maximum();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return 0;
}

void stack::set_configuration_wallet_transaction_fee(const std::int64_t & val)
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_wallet_transaction_fee(val);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

const std::int64_t stack::configuration_wallet_transaction_fee() const
{
    if (stack_impl_)
    {
        return stack_impl_->configuration_wallet_transaction_fee();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return 0;
}

void stack::set_configuration_network_tcp_read_maximum(
    const std::size_t & val
    )
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_network_tcp_read_maximum(val);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

const std::size_t stack::configuration_network_tcp_read_maximum() const
{
    if (stack_impl_)
    {
        return stack_impl_->configuration_network_tcp_read_maximum();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return 0;
}

void stack::set_configuration_network_tcp_write_maximum(
    const std::size_t & val
    )
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_network_tcp_write_maximum(val);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

const std::size_t stack::configuration_network_tcp_write_maximum() const
{
    if (stack_impl_)
    {
        return stack_impl_->configuration_network_tcp_write_maximum();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return 0;
}

void stack::on_status(const std::map<std::string, std::string> & pairs)
{
    log_none("Stack got info, pairs = " << pairs.size() << ".");
}

void stack::on_status(
    const std::vector< std::map<std::string, std::string> > & pairs
    )
{
    log_none("Stack got info, pairs = " << pairs.size() << ".");
}
