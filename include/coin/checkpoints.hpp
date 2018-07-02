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

#ifndef COIN_CHECKPOINTS_HPP
#define COIN_CHECKPOINTS_HPP

#include <cstdint>
#include <map>
#include <mutex>

#include <coin/sha256.hpp>


#include <coin/block_index.hpp>
#include <coin/globals.hpp>

namespace coin {

    class block_index;
    
    /**
     * Implements checkpoints.
     */
    class checkpoints
    {
        public:
        
            /**
             * Constructor
             */
            checkpoints();
        
            /**
             * The singleton accessor.
             */
            static checkpoints & instance();
        
            /**
             * Checks hardend checkpoints.
             * @param height The block height.
             * @param hash The sha256.
             */
            bool check_hardened(
                const std::int32_t & height, const sha256 & hash
            );

            /**
             * Returns an estimate of total number of blocks, 0 if unknown.
             */
            std::uint32_t get_total_blocks_estimate();

            /**
             * Returns (SPV) checkpoints (height, hash, timestamp).
             */
            std::map<std::int32_t, std::pair<sha256, std::time_t> >
                get_spv_checkpoints()
            ;

            /**
             * The checkpoints.
             */
            std::map<int, sha256> get_checkpoints();
        
            /**
             * The test net check points.
             */
            std::map<int, sha256> get_checkpoints_test_net();

        private:
    
            /**
             * The checkpoints.
             */
            std::map<std::int32_t, sha256> m_checkpoints;
        
            /**
             * The test net checkpoints.
             */
            std::map<std::int32_t, sha256> m_checkpoints_test_net;
        
        protected:
        
            /**
             * The std::recursive_mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CHECKPOINTS_HPP
