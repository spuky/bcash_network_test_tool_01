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

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/checkpoints.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>

using namespace coin;

checkpoints::checkpoints()
{
    m_checkpoints[0] = block::get_hash_genesis();
    m_checkpoints[20160] = sha256(
        "000000000f1aef56190aee63d33a373e6487132d522ff4cd98ccfc96566d461e"
    );
    m_checkpoints[40320] = sha256(
        "0000000045861e169b5a961b7034f8de9e98022e7a39100dde3ae3ea240d7245"
    );
    m_checkpoints[60480] = sha256(
        "000000000632e22ce73ed38f46d5b408ff1cff2cc9e10daaf437dfd655153837"
    );
    m_checkpoints[80640] = sha256(
        "0000000000307c80b87edf9f6a0697e2f01db67e518c8a4d6065d1d859a3a659"
    );
    m_checkpoints[100800] = sha256(
        "000000000000e383d43cc471c64a9a4a46794026989ef4ff9611d5acb704e47a"
    );
    
    /**
     * After the Bitcoin Cash Fork at block 478558.
     */
    m_checkpoints[484400] = sha256(
        "000000000000000000f5fa8aad9aab5c42341eb3381d46668585920a50829d12"
    );
    
    m_checkpoints_test_net[0] = block::get_hash_genesis_test_net();
}

checkpoints & checkpoints::instance()
{
    static checkpoints g_checkpoints;
            
    return g_checkpoints;
}

bool checkpoints::check_hardened(
    const std::int32_t & height, const sha256 & hash
    )
{
    auto & checkpoints =
        (constants::test_net ?
        m_checkpoints_test_net : m_checkpoints)
    ;

    auto it = checkpoints.find(height);
    
    if (it == checkpoints.end())
    {
        return true;
    }
    
    return hash == it->second;
}

std::uint32_t checkpoints::get_total_blocks_estimate()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (globals::instance().is_client_spv() == true)
    {
        if (get_spv_checkpoints().size() > 0)
        {
            return get_spv_checkpoints().rbegin()->first;
        }
        
        return 0;
    }
    
    return (
        constants::test_net ? m_checkpoints_test_net : m_checkpoints
    ).rbegin()->first;
}

std::map<std::int32_t, std::pair<sha256, std::time_t> >
    checkpoints::get_spv_checkpoints()
{
    /**
     * The checkpoint timestamps.
     */
    std::map<std::int32_t, std::pair<sha256, std::time_t> > ret;
    
    /**
     * The test net doesn't have checkpoints.
     */
    if (constants::test_net == true)
    {
        return ret;
    }

	ret[0] = std::make_pair(sha256(
		block::get_hash_genesis().to_string()), 1231006505
	);
    ret[20160] = std::make_pair(sha256(
        "000000000f1aef56190aee63d33a373e6487132d522ff4cd98ccfc96566d461e"),
        1248481816
    );
    ret[40320] = std::make_pair(sha256(
        "0000000045861e169b5a961b7034f8de9e98022e7a39100dde3ae3ea240d7245"),
        1266191579
    );
    ret[60480] = std::make_pair(sha256(
        "000000000632e22ce73ed38f46d5b408ff1cff2cc9e10daaf437dfd655153837"),
        1276298786
    );
    ret[80640] = std::make_pair(sha256(
        "0000000000307c80b87edf9f6a0697e2f01db67e518c8a4d6065d1d859a3a659"),
        1284861847
    );
    ret[100800] = std::make_pair(sha256(
        "000000000000e383d43cc471c64a9a4a46794026989ef4ff9611d5acb704e47a"),
        1294031411
    );
    ret[120960] = std::make_pair(sha256(
        "0000000000002c920cf7e4406b969ae9c807b5c4f271f490ca3de1b0770836fc"),
        1304131980
    );
    ret[141120] = std::make_pair(sha256(
        "00000000000002d214e1af085eda0a780a8446698ab5c0128b6392e189886114"),
        1313451894
    );
    ret[161280] = std::make_pair(sha256(
        "00000000000005911fe26209de7ff510a8306475b75ceffd434b68dc31943b99"),
        1326047176
    );
    ret[181440] = std::make_pair(sha256(
        "00000000000000e527fc19df0992d58c12b98ef5a17544696bbba67812ef0e64"),
        1337883029
    );
    ret[201600] = std::make_pair(sha256(
        "00000000000003a5e28bef30ad31f1f9be706e91ae9dda54179a95c9f9cd9ad0"),
        1349226660
    );
    ret[221760] = std::make_pair(sha256(
        "00000000000000fc85dd77ea5ed6020f9e333589392560b40908d3264bd1f401"),
        1361148470
    );
    ret[241920] = std::make_pair(sha256(
        "00000000000000b79f259ad14635739aaf0cc48875874b6aeecc7308267b50fa"),
        1371418654
    );
    ret[262080] = std::make_pair(sha256(
        "000000000000000aa77be1c33deac6b8d3b7b0757d02ce72fffddc768235d0e2"),
        1381070552
    );
    ret[282240] = std::make_pair(sha256(
        "0000000000000000ef9ee7529607286669763763e0c46acfdefd8a2306de5ca8"),
        1390570126
    );
    ret[302400] = std::make_pair(sha256(
        "0000000000000000472132c4daaf358acaf461ff1c3e96577a74e5ebf91bb170"),
        1400928750
    );
    ret[322560] = std::make_pair(sha256(
        "000000000000000002df2dd9d4fe0578392e519610e341dd09025469f101cfa1"),
        1411680080
    );
    ret[342720] = std::make_pair(sha256(
        "00000000000000000f9cfece8494800d3dcbf9583232825da640c8703bcd27e7"),
        1423496415
    );
    ret[362880] = std::make_pair(sha256(
        "000000000000000014898b8e6538392702ffb9450f904c80ebf9d82b519a77d5"),
        1435475246
    );
    ret[383040] = std::make_pair(sha256(
        "00000000000000000a974fa1a3f84055ad5ef0b2f96328bc96310ce83da801c9"),
        1447236692
    );
    ret[403200] = std::make_pair(sha256(
        "000000000000000000c4272a5c68b4f55e5af734e88ceab09abf73e9ac3b6d01"),
        1458292068
    );
    ret[423360] = std::make_pair(sha256(
        "000000000000000001630546cde8482cc183708f076a5e4d6f51cd24518e8f85"),
        1470163842
    );
    ret[443520] = std::make_pair(sha256(
        "00000000000000000345d0c7890b2c81ab5139c6e83400e5bed00d23a1f8d239"),
        1481765313
    );
    ret[484400] = std::make_pair(sha256(
        "000000000000000000f5fa8aad9aab5c42341eb3381d46668585920a50829d12"),
        1504972523
    );
    
    return ret;
}

std::map<int, sha256> checkpoints::get_checkpoints()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_checkpoints.size() == 0)
    {
        /**
         * Add any checkpoints here.
         */
        m_checkpoints[0] = block::get_hash_genesis();
    }
    
    return m_checkpoints;
}

std::map<int, sha256> checkpoints::get_checkpoints_test_net()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_checkpoints_test_net.size() == 0)
    {
        /**
         * Add any checkpoints here.
         */
        m_checkpoints_test_net[0] =
            block::get_hash_genesis_test_net()
        ;
    }
    
    return m_checkpoints_test_net;
}
