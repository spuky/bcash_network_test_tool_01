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

#ifndef COIN_MINING_MANAGER_HPP
#define COIN_MINING_MANAGER_HPP

/**
 * Workaround bug in gcc 4.7:  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52680
 */
#if (defined __linux__)
#define _GLIBCXX_USE_NANOSLEEP 1
#endif // __linux__

#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace coin {

    class key_reserved;
    class stack_impl;
    
    /**
     * Implements a mining manager.
     */
    class mining_manager
    {
        public:
        
            /**
             * The Proof-of-Work states.
             */
            typedef enum
            {
                state_pow_none,
                state_pow_starting,
                state_pow_started,
                state_pow_stopping,
                state_pow_stopped
            } state_pow_t;
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param owner The stack_impl.
             */
            mining_manager(
                boost::asio::io_service & ios, stack_impl & owner
            );
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Starts mining Proof-of-Work.
             */
            void start_proof_of_work();
        
            /**
             * Stops mining Proof-of-Work.
             */
            void stop_proof_of_work();
        
            /**
             * The number of hashes per second.
             */
            const double & hashes_per_second() const;
        
        private:

            /**
             * The main loop.
             * @param cores The number of hasing cores.
             * @param thread_index The thread index.
             */
            void loop(
            	const std::uint32_t & cores, const std::uint32_t & thread_index
            );

            /**
             * The state_pow_t.
             */
            state_pow_t m_state_pow;
        
            /**
             * The number of hashes per second.
             */
            double m_hashes_per_second;
        
            /**
             * The time the hps timer was started.
             */
            std::int64_t m_hps_timer_start;

        protected:
        
            /**
             * Checks the work.
             * @param blk The block.
             * @paramw w The wallet.
             * @param reserved_key The key_reserved.
             */
            void check_work(
                std::shared_ptr<block> & blk,
                const std::shared_ptr<wallet> & w,
                key_reserved & reserve_key
            );
        
            /**
             * Increments the extra nonce.
             * @param blk The block.
             * @param index_previous The previous block_index.
             * @param extra_nonce The extra nonce.
             */
            void increment_extra_nonce(
                std::shared_ptr<block> & blk, block_index * index_previous,
                std::uint32_t & extra_nonce
            );
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;

            /**
             * The std::mutex
             */
            mutable std::mutex mutex_;
        
            /**
             * The (Proof-of-Work) threads.
             */
            std::vector< std::shared_ptr<std::thread> > threads_;
    };
    
} // namespace coin

#endif // COIN_MINING_MANAGER_HPP
