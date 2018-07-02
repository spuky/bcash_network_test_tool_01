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

#ifndef COIN_NETWORK_HPP
#define COIN_NETWORK_HPP

#include <array>
#include <clocale>
#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include <boost/format.hpp>

#include <coin/logger.hpp>

namespace coin {

    /**
     * Implements network related functionality.
     */
    class network
    {
        public:
        
            /**
             * Constructor
             */
            network()
            {
                /**
                 * Insert the "always" allowed RPC IP addresses.
                 */
                m_allowed_addresses_rpc.insert("127.0.0.1");
                m_allowed_addresses_rpc.insert("::1");
            }
        
            /**
             * The singleton accessor.
             */
            static network & instance()
            {
                static network g_network;
                
                return g_network;
            }
        
            /**
             * The minimum number of inbound TCP connections.
             */
            enum { tcp_inbound_minimum = 16 };
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
			enum { tcp_inbound_maximum = 24 };
#else
            /**
             * The maximum number of inbound TCP connections.
             */
            enum { tcp_inbound_maximum = 128 };
#endif // BCASH_STRESS_TEST
            /**
             * rfc1123 time.
             */
            std::string rfc1123_time()
            {
                char buf[64];
                
                std::time_t now;
                
                std::time(&now);
                
                struct tm * now_gmt = std::gmtime(&now);
                
                std::string locale(setlocale(LC_TIME, 0));
                
                std::setlocale(LC_TIME, "C");
                
                std::strftime(
                    buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", now_gmt
                );
                
                std::setlocale(LC_TIME, locale.c_str());
                
                return std::string(buf);
            }
        
            /**
             * The allowed addresses.
             */
            std::set<std::string> & allowed_addresses_rpc()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_allowed_addresses_rpc;
            }
        
            /**
             * The banned addresses.
             */
            std::map<std::string, std::time_t> & banned_addresses()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_banned_addresses;
            }
        
            /**
             * Bans an address for seconds.
             * @param addr The address.
             * @param seconds The seconds.
             */
            void ban_address(
                const std::string & addr,
                const std::uint32_t & seconds = 24 * 60 * 60
                )
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                log_info(
                    "Network is banning address " << addr << ", for " <<
                    seconds / 60 / 60 << " hours."
                );
                
                m_banned_addresses[addr] = std::time(0) + seconds;
            }
        
            /**
             * If true the address is banned.
             * @param addr The address.
             */
            bool is_address_banned(const std::string & addr)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                auto it = m_banned_addresses.find(addr);
                
                if (it != m_banned_addresses.end())
                {
                    if (std::time(0) < it->second)
                    {
                        return true;
                    }
                    else
                    {
                        /**
                         * The address is no longer banned, erase it.
                         */
                        m_banned_addresses.erase(it);
                        
                        return false;
                    }
                }
                
                return false;
            }
        
            /**
             * If true the address is allowed.
             * @param addr The address.
             */
            bool is_address_rpc_allowed(const std::string & addr)
            {
                return
                    m_allowed_addresses_rpc.find(addr) !=
                    m_allowed_addresses_rpc.end()
                ;
            }
        
            /**
             * Formats bytes into a (human friendly) byte string.
             * @param bytes The bytes.
             */
            static std::string format_byte_string(
                const std::size_t & bytes
                )
            {
                auto bytes_float = static_cast<float> (bytes);
    
                static std::array<std::string, 7> byte_units =
                {
                    "B", "KB", "MB", "GB", "TB", "PB", "EB"
                };
                
                auto index = 0;
                
                while (bytes_float >= 1024 && index < byte_units.size() - 1)
                {
                    index++;
                    
                    bytes_float /= 1024.0f;
                }
                
                return
                    (boost::format("%.02f %s") %
                    bytes_float % byte_units[index].c_str()).str()
                ;
            }
        
            /**
             * Formats bytes into a bandwidth string.
             * @param bytes The bytes.
             */
            static std::string format_bandwidth_string(
                const std::size_t & bytes
                )
            {
                auto bytes_float = static_cast<float> (bytes);
    
                static std::array<std::string, 7> byte_units =
                {
                    "B", "KB", "MB", "GB", "TB", "PB", "EB"
                };
                
                auto index = 0;
                
                while (bytes_float >= 1024 && index < byte_units.size() - 1)
                {
                    index++;
                    
                    bytes_float /= 1024.0f;
                }
                
                return
                    (boost::format("%.02f %s%s") %
                    bytes_float % byte_units[index].c_str() % "/s").str()
                ;
            }
        
        private:
        
            /**
             * The allowed addresses.
             */
            std::set<std::string> m_allowed_addresses_rpc;
        
            /**
             * The banned addresses.
             */
            std::map<std::string, std::time_t> m_banned_addresses;
        
        protected:
        
            /**
             * The std::mutex.
             */
            std::mutex mutex_;
    };
}

#endif // COIN_NETWORK_HPP
