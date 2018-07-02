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

#ifndef COIN_CONFIGURATION_HPP
#define COIN_CONFIGURATION_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace coin {

    /**
     * The configuration.
     */
    class configuration
    {
        public:
        
            /**
             * The version.
             */
            enum { version = 1 };
        
            /**
             * Constructor
             */
            configuration();
        
            /**
             * Loads
             */
            bool load();
        
            /**
             * Saves
             */
            bool save();

            /**
             * Sets the arguments.
             * @param val The arguments.
             */
            void set_args(const std::map<std::string, std::string>  & val);
        
            /** 
             * The arguments.
             */
            std::map<std::string, std::string> & args();
        
            /**
             * Sets the network TCP port.
             */
            void set_network_port_tcp(const std::uint16_t & val);
        
            /**
             * The network TCP port.
             */
            const std::uint16_t & network_port_tcp() const;
        
            /**
             * Sets the maximum number of inbound TCP connections.
             * @param val The value.
             */
            void set_network_tcp_inbound_maximum(const std::size_t & val);
        
            /**
             * The maximum number of inbound TCP connections;
             */
            const std::size_t & network_tcp_inbound_maximum() const;
        
            /**
             * Sets the maximum number bytes read per second.
             * @param val The value.
             */
            void set_network_tcp_read_maximum(const std::size_t & val);
        
            /**
             * The maximum number bytes read per second.
             */
            const std::size_t & network_tcp_read_maximum() const;
        
            /**
             * Sets the maximum number bytes written per second.
             * @param val The value.
             */
            void set_network_tcp_write_maximum(const std::size_t & val);
        
            /**
             * The maximum number bytes written per second.
             */
            const std::size_t & network_tcp_write_maximum() const;
            
            /**
             * Sets the bootstrap nodes.
             * @param val The 
             */
            void set_bootstrap_nodes(
                const std::vector< std::pair<std::string, std::uint16_t> > & val
                )
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                m_bootstrap_nodes = val;
            }
        
            /**
             * The bootstrap nodes.
             */
            std::vector<
                std::pair<std::string, std::uint16_t>
                > & bootstrap_nodes()
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                return m_bootstrap_nodes;
            }
        
            /**
             * The bootstrap nodes.
             */
            const std::vector<
                std::pair<std::string, std::uint16_t>
                > & bootstrap_nodes() const
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                return m_bootstrap_nodes;
            }
        
            /**
             * Sets the wallet.transaction.history.maximum
             * @param val The value.
             */
            void set_wallet_transaction_history_maximum(
                const std::time_t & val
                )
            {
                m_wallet_transaction_history_maximum = val;
            }
        
            /**
             * The maximum transaction history.
             */
            const std::time_t & wallet_transaction_history_maximum() const
            {
                return m_wallet_transaction_history_maximum;
            }
        
            /**
             * Sets the wallet.transaction.fee
             * @param val The value.
             */
            void set_wallet_transaction_fee(const std::int64_t & val)
            {
                m_wallet_transaction_fee = val;
            }
        
            /**
             * The wallet transaction fee.
             */
            const std::int64_t & wallet_transaction_fee() const
            {
                return m_wallet_transaction_fee;
            }
        
            /**
             * The wallet keypool size.
             */
            const std::int32_t & wallet_keypool_size() const
            {
                return m_wallet_keypool_size;
            }
        
            /**
             * Set wallet rescan.
             * @param val The value.
             */
            void set_wallet_rescan(const bool & val)
            {
                m_wallet_rescan = val;
            }
        
            /**
             * Wallet rescan.
             */
            const bool & wallet_rescan() const
            {
                return m_wallet_rescan;
            }
        
            /**
             * Sets the database cache size.
             * @param val The value.
             */
            void set_database_cache_size(const std::uint32_t & val);
        
            /**
             * The database cache size.
             */
            const std::uint32_t & database_cache_size() const;
        
            /**
             * Sets if the wallet is deterministic.
             * @param val The value.
             */
            void set_wallet_deterministic(const bool & val);
        
            /**
             * If true the wallet is deterministic.
             */
            const bool & wallet_deterministic() const;
        
            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             * @param val The value.
             */
            void set_db_private(const bool & val);
        
            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             */
            const bool & db_private() const;
        
            /**
             * The RPC (local) whitelist.
             */
            const std::string & rpc_local_whitelist() const;
        
        private:
        
            /** 
             * The arguments.
             */
            std::map<std::string, std::string> m_args;
        
            /**
             * The network TCP port.
             */
            std::uint16_t m_network_port_tcp;
        
            /**
             * The maximum number of inbound TCP connections;
             */
            std::size_t m_network_tcp_inbound_maximum;

            /**
             * The maximum number bytes read per second.
             */
            std::size_t m_network_tcp_read_maximum;
        
            /**
             * The maximum number bytes written per second.
             */
            std::size_t m_network_tcp_write_maximum;
            
            /**
             * The bootstrap nodes.
             */
            std::vector<
                std::pair<std::string, std::uint16_t>
            > m_bootstrap_nodes;
        
            /**
             * The maximum wallet transaction history.
             */
            std::time_t m_wallet_transaction_history_maximum;
        
            /**
             * The wallet transaction fee.
             */
            std::int64_t m_wallet_transaction_fee;
        
            /**
             * The wallet keypool size.
             */
            std::int32_t m_wallet_keypool_size;
        
            /**
             * The wallet rescan.
             */
            bool m_wallet_rescan;
        
            /**
             * The database cache size.
             */
            std::uint32_t m_database_cache_size;
        
            /**
             * If true the wallet is deterministic.
             */
            bool m_wallet_deterministic;

            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             */
            bool m_db_private;
        
            /**
             * The RPC (local) whitelist.
             */
            std::string m_rpc_local_whitelist;
            
        protected:
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CONFIGURATION_HPP
