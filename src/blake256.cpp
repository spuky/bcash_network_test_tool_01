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

#include <coin/blake256.hpp>

#ifdef __cplusplus
extern "C"{
#endif
#include <coin/sph_blake.h>
#ifdef __cplusplus
}
#endif

using namespace coin;

blake256::digest_t blake256::hash(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    digest_t ret;
    
    sph_blake256_context ctx;
    sph_blake256_init(&ctx);
    sph_blake256(&ctx, buf, len);
    sph_blake256_close(&ctx, &ret[0]);

    return ret;
}
