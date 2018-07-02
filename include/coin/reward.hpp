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

#ifndef COIN_REWARD_HPP
#define COIN_REWARD_HPP

#include <cstdint>

#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements various reward algorithms.
     */
    class reward
    {
        public:
        
            /**
             * Miner's coin base reward.
             * @param height The height.
             * @param fees The fees.
             * @param hash_previous The sha256.
             */
            static std::int64_t get_proof_of_work(
                const std::int32_t & height, const std::int64_t & fees,
                const sha256 & hash_previous
            );
        
        private:

            // ...
        
        protected:
    
            // ...
    };

} // namespace coin

#endif // COIN_REWARD_HPP
