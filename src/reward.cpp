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

#include <cmath>

#include <coin/constants.hpp>
#include <coin/logger.hpp>
#include <coin/reward.hpp>

using namespace coin;

std::int64_t reward::get_proof_of_work(
    const std::int32_t & height, const std::int64_t & fees,
    const sha256 & hash_previous
    )
{
    /**
     * Set the initial block reward (subsidy).
     */
    std::int64_t subsidy = 50 * constants::coin;

    /**
     * Split every 210000 blocks (~4 years).
     */
    subsidy >>= (height / 210000);

    /**
     * Give fees to Proof-of-Work solution solvers (miners).
     */
    return subsidy + fees;
}
