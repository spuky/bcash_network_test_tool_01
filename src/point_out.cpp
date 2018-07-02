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

#include <coin/logger.hpp>
#include <coin/point_out.hpp>

using namespace coin;

point_out::point_out()
    : data_buffer()
    , m_hash()
    , m_n(-1)
{
    // ...
}

point_out::point_out(const sha256 & h, const std::int32_t & n)
    : data_buffer()
    , m_hash(h)
    , m_n(n)
{
    // ...
}

void point_out::encode()
{
    write_sha256(m_hash);
    write_int32(m_n);
}

void point_out::decode()
{
    m_hash = read_sha256();
    m_n = read_int32();
}

void point_out::set_null()
{
    m_hash.clear(), m_n = -1;
}

bool point_out::is_null() const
{
    return m_hash == 0 && m_n == -1;
}

const sha256 & point_out::get_hash() const
{
    return m_hash;
}

const std::int32_t & point_out::n() const
{
    return m_n;
}

const std::string point_out::to_string() const
{
    return
        "point out(" + m_hash.to_string().substr(0, 4) + ", " +
        std::to_string(m_n) + ")"
    ;
}

