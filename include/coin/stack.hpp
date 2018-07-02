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
 
#ifndef COIN_STACK_HPP
#define COIN_STACK_HPP

#include <cstdint>
#include <ctime>
#include <map>
#include <string>
#include <vector>

namespace coin {

    class stack_impl;
    
    /**
     * The stack.
     */
    class stack
    {
        public:
        
            /**
             * Constructor
             */
            stack();
            
            /**
             * Starts the stack.
             * @param args The arguments.
             */
            void start(
                const std::map<std::string, std::string> & args =
                std::map<std::string, std::string> ()
            );
            
            /**
             * Stops the stack.
             */
            void stop();
        
            /**
             * Connects to the network.
             */
            void connect();
        
            /**
             * Disconnects from the network.
             */
            void disconnect();
        
            /**
             * Sends coins.
             * @param amount The amount.
             * @param destination The destination.
             * @param wallet_values The wallet key/values.
             */
            void send_coins(
                const std::int64_t & amount, const std::string & destination,
                const std::map<std::string, std::string> & wallet_values
            );
        
            /**
             * Queues coins.
             * @param amount The amount.
             * @param destination The destination.
             * @param wallet_values The wallet key/values.
             */
            void queue_coins(
                const std::int64_t & amount, const std::string & destination,
                const std::map<std::string, std::string> & wallet_values
            );
        
            /**
             * Sends any queued coins.
             */
            void send_queued_coins();
        
            /**
             * Cancels any queued coins.
             */
            void cancel_queued_coins();
        
            /** 
             * Starts mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void start_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /** 
             * Stops mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void stop_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /**
             * If true a wallet file exists.
             */
            static bool wallet_exists(const bool & is_client);
        
            /**
             * Encrypts the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_encrypt(const std::string & passphrase);
        
            /**
             * Locks the wallet.
             */
            void wallet_lock();
            
            /**
             * Unlocks the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_unlock(const std::string & passphrase);
        
            /**
             * Changes the wallet passphrase.
             * @param passphrase_old The old passphrase.
             * @param password_new The new passphrase.
             */
            void wallet_change_passphrase(
                const std::string & passphrase_old,
                const std::string & password_new
            );
        
            /**
             * If true the wallet is crypted.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_crypted(const std::uint32_t & wallet_id = 0);
        
            /**
             * If true the wallet is locked.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_locked(const std::uint32_t & wallet_id = 0);
        
            /**
             * Get's the wallet HD keychain seed (if configured).
             */
            std::string wallet_hd_keychain_seed();
        
            /**
             * Generates a new wallet address.
             * @param label The label.
             */
            void wallet_generate_address(const std::string & label);
        
            /**
             * Sends an RPC command line.
             * @param command_line The command line.
             */
            void rpc_send(const std::string & command_line);
        
            /**
             * Rescans the chain.
             * @param time_from The time fromm where to begin the rescan of the
             * chain headers.
             */
            void rescan_chain(const std::int64_t & time_from = 0);
        
            /**
             * Bans an IP Address or Endpoint for duration.
             * @param ip_or_endpoint An IP Address or Endpoint.
             * @param duration The duration.
             */
            void ban_ip_address(
                const std::string & ip_or_endpoint,
                const std::uint32_t & duration
            );
        
            /**
             * Sets the wallet.transaction.history.maximum
             * @param val The value.
             */
            void set_configuration_wallet_transaction_history_maximum(
                const std::time_t & val
            );
        
            /**
             * The wallet.transaction.history.maximum.
             */
            const std::time_t
                configuration_wallet_transaction_history_maximum() const
            ;
        
            /**
             * Sets the wallet.transaction.fee
             * @param val The value.
             */
            void set_configuration_wallet_transaction_fee(
                const std::int64_t & val
            );
        
            /**
             * The wallet.transaction.fee.
             */
            const std::int64_t configuration_wallet_transaction_fee() const;
        
            /**
             * Sets the network.tcp.read.maximum.
             * @param val The value.
             */
            void set_configuration_network_tcp_read_maximum(
                const std::size_t & val
            );
        
            /**
             * The network.tcp.read.maximum.
             */
            const std::size_t configuration_network_tcp_read_maximum() const;
        
            /**
             * Sets the network.tcp.write.maximum.
             * @param val The value.
             */
            void set_configuration_network_tcp_write_maximum(
                const std::size_t & val
            );
        
            /**
             * The network.tcp.write.maximum.
             */
            const std::size_t configuration_network_tcp_write_maximum() const;
        
            /**
             * Called when an error occurs.
             * @param pairs The key/value pairs.
             */
            virtual void on_error(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when a status update occurs.
             * @param pairs The key/value pairs.
             */
            virtual void on_status(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when a status update occurs.
             * @param pairs An std::vector of key/value pairs.
             */
            virtual void on_status(
                const std::vector< std::map<std::string, std::string> > & pairs
            );
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The stack implementation.
             */
            stack_impl * stack_impl_;
    };

} // namespace coin

#endif // COIN_STACK_HPP
