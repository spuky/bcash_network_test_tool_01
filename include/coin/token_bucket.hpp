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

#ifndef COIN_TOKEN_BUCKET_HPP
#define COIN_TOKEN_BUCKET_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

namespace coin {

    /**
     * The token bucket is an algorithm used in packet switched computer
     * networks and telecommunications networks. It can be used to check that
     * data transmissions, in the form of packets, conform to defined limits on
     * bandwidth and burstiness (a measure of the unevenness or variations in
     * the traffic flow). It can also be used as a scheduling algorithm to
     * determine the timing of transmissions that will comply with the limits
     * set for then bandwidth and burstiness.
     */
    class token_bucket
    {
        public:
        
            /**
             * Constructor
             */
            token_bucket()
                : m_is_enabled(true)
                , m_time(0)
                , m_rate(0)
                , m_time_per_token(0)
                , m_time_per_burst(0)
            {
                // ...
            }

            /**
             * Constructor
             * @param rate The rate.
             * @param burst The burst.
             */
            token_bucket(const std::size_t & rate, const std::size_t & burst)
                : m_is_enabled(true)
                , m_rate(rate)
                , m_time(0)
                , m_time_per_token(1000000 / m_rate)
                , m_time_per_burst(burst * m_time_per_token)
            {
                // ...
            }

            /**
             * Copy Constructor
             * @param other The other token_bucket.
             */
            token_bucket(const token_bucket & other)
            {
                m_is_enabled = other.m_is_enabled.load();
                m_time_per_token = other.m_time_per_token.load();
                m_time_per_burst = other.m_time_per_burst.load();
            }

            /**
             * operator =
             * @param other The other token_bucket.
             */
            token_bucket & operator = (const token_bucket & other)
            {
                m_is_enabled = other.m_is_enabled.load();
                m_time_per_token = other.m_time_per_token.load();
                m_time_per_burst = other.m_time_per_burst.load();
                
                return *this;
            }
        
            /**
             * If true we enforce the token and burst rates.
             * @param val The value.
             */
            void set_is_enabled(const bool & val)
            {
                m_is_enabled.store(val, std::memory_order_relaxed);
            }
        
            /**
             * If true we enforce the token and burst rates.
             */
            const bool is_enabled() const
            {
                return m_is_enabled.load(std::memory_order_relaxed);
            }
        
            /**
             * The rate.
             */
            const std::size_t rate() const
            {
                return m_rate.load(std::memory_order_relaxed);
            }
        
            /**
             * The time per token.
             * @param val The value.
             */
            void set_time_per_token(const std::uint64_t & val)
            {
                m_time_per_token.store(
                    1000000 / val, std::memory_order_relaxed
                );
            }
            
            /**
             * The time per burst.
             * @param val The value.
             */
            void set_time_per_burst(const std::uint64_t & val)
            {
                m_time_per_burst.store(
                    val * m_time_per_token, std::memory_order_relaxed
                );
            }

            /**
             * Attempt to consume the given number of tokens.
             * @param tokens The number of tokens.
             */
            bool try_to_consume(const std::size_t & tokens)
            {
                if (m_is_enabled == true)
                {
                    const auto now =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()
                        ).count()
                    ;
                    
                    const auto time_needed =
                        tokens * m_time_per_token.load(std::memory_order_relaxed)
                    ;
                    
                    const auto time_min =
                        now - m_time_per_burst.load(std::memory_order_relaxed)
                    ;
               
                    auto time_old = m_time.load(std::memory_order_relaxed);
                    
                    auto time_new = time_old;

                    if (time_min > time_old)
                    {
                        time_new = time_min;
                    }

                    while (true)
                    {
                        time_new += time_needed;
                  
                        if (time_new > now)
                        {
                            return false;
                        }
                  
                        if (
                            m_time.compare_exchange_weak(time_old, time_new,
                            std::memory_order_relaxed, std::memory_order_relaxed)
                            )
                        {
                            return true;
                        }
                    
                        time_new = time_old;
                    }

                    return false;
                }
                
                return true;
            }
        
            /**
             * Runs test case.
             */
            static int run_test()
            {
                auto consumed = 0;
                
                std::size_t len_rate = 64000;
                std::size_t len_burst = 128000;
                
                auto rate_limit = true;
                
                token_bucket tb =
                    rate_limit ?
                    token_bucket(len_rate, len_burst) : token_bucket()
                ;

                for (auto i = 0; i < 1024; i++)
                {
                    auto bytes_to_consume =
                        static_cast<std::size_t>(std::rand() % len_burst)
                    ;
                    
                    if (tb.try_to_consume(bytes_to_consume) == true)
                    {
                        consumed++;
                        
                        std::cout <<
                            "token_bucket::try_to_consume[" << consumed <<
                            "] " << bytes_to_consume << " bytes\n"
                        ;
                    }
                    else
                    {
                        std::cout << "token_bucket::is non-conformant...\n";
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                }
            
                return 0;
            }
        
        private:
        
            /**
             * If true we enforce the token and burst rates.
             */
            std::atomic<bool> m_is_enabled;
    
            /**
             * The rate.
             */
            std::atomic<std::size_t> m_rate;
        
            /**
             * The time.
             */
            std::atomic<std::uint64_t> m_time;
    
            /**
             * The time per token.
             */
            std::atomic<std::uint64_t> m_time_per_token;
        
            /**
             * The time per burst.
             */
            std::atomic<std::uint64_t> m_time_per_burst;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_TOKEN_BUCKET_HPP
