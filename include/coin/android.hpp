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

#ifndef COIN_ANDROID_HPP
#define COIN_ANDROID_HPP

#if (defined __ANDROID__)
#include <boost/lexical_cast.hpp>
#endif // __ANDROID__

#if (defined __ANDROID__)
namespace std {
    
    template<typename T>
    std::string to_string(const T & val)
    {
        return boost::lexical_cast<std::string> (val);
    }
    
    template<typename T>
    unsigned long stoul(const T & val)
    {
        return boost::lexical_cast<unsigned long> (val);
    }
    
    template<typename T>
    int stoi(const T & val)
    {
        return boost::lexical_cast<int> (val);
    }
}
#endif // __ANDROID__


#endif // COIN_ANDROID_HPP
