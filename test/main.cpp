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

#define COIN_RUN_TEST_CASES 0

#include <iostream>

#include <boost/asio.hpp>

#pragma comment(lib, "Shell32.lib")
#if (defined _DEBUG)
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\libeay32MTd.lib")
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\ssleay32MTd.lib")
// build with project file in build_windows
#pragma comment(lib, "..\\deps\\platforms\\windows\\db\\build_windows\\Win32\\Debug_static\\libdb61sd.lib")
#else
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\libeay32MT.lib")
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\ssleay32MT.lib")
// build with project file in build_windows
#pragma comment(lib, "..\\deps\\platforms\\windows\\db\\build_windows\\Win32\\Release_static\\libdb61s.lib")
#endif

#if (defined COIN_RUN_TEST_CASES && COIN_RUN_TEST_CASES)
#include <coin/block.hpp>
#include <coin/key.hpp>
#include <coin/nat_pmp_client.hpp>
#include <coin/tcp_acceptor.hpp>
#else
#include <coin/stack.hpp>
#endif

int main(int argc, const char * argv[])
{
    int ret = 0;

#if (defined COIN_RUN_TEST_CASES && COIN_RUN_TEST_CASES)

#define COIN_RUN_TEST_CASE_BLOCK 0
#define COIN_RUN_TEST_CASE_KEY 1
#define COIN_RUN_TEST_CASE_NAT_PMP 0
#define COIN_RUN_TEST_CASE_TCP_ACCEPTOR 0

#if (defined COIN_RUN_TEST_CASE_BLOCK && COIN_RUN_TEST_CASE_BLOCK)
    ret |= coin::block::run_test();
#endif // COIN_RUN_TEST_CASE_BLOCK

#if (defined COIN_RUN_TEST_CASE_KEY && COIN_RUN_TEST_CASE_KEY)
    ret |= coin::key::run_test();
#endif // COIN_RUN_TEST_CASE_KEY

#if (defined COIN_RUN_TEST_CASE_NAT_PMP && COIN_RUN_TEST_CASE_NAT_PMP)
    ret |= coin::nat_pmp_client::run_test();
#endif // COIN_RUN_TEST_CASE_NAT_PMP

#if (defined COIN_RUN_TEST_CASE_TCP_ACCEPTOR && COIN_RUN_TEST_CASE_TCP_ACCEPTOR)
    boost::asio::io_service ios;
    
    ret |= coin::tcp_acceptor::run_test(ios);
    
    ios.run();
#endif // COIN_RUN_TEST_CASE_TCP_ACCEPTOR
#else
    /**
     * Allocate the stack.
     */
    coin::stack s;
    
    std::map<std::string, std::string> args;
    
    for (auto i = 0; i < argc; i++)
    {
        if (argv[i][0] == '-' && argv[i][1] == '-')
        {
            std::string arg = std::string(argv[i]).substr(2, strlen(argv[i]));
            
            std::string key, value;
            
            auto i = arg.find("=");

            if (i != std::string::npos)
            {
                key = arg.substr(0, i);
                
                i = arg.find("=");
                
                if (i != std::string::npos)
                {
                    value = arg.substr(i + 1, strlen(argv[i]));
                    
                    args[key] = value;
                }
            }
        }
    }
    
    /**
     * Start the stack.
     */
    s.start(args);

    /**
     * Wait for termination.
     */
    boost::asio::io_service ios;
    boost::asio::signal_set signals(ios, SIGINT, SIGTERM);
    signals.async_wait(std::bind(&boost::asio::io_service::stop, &ios));
    ios.run();

    /**
     * Stop the stack.
     */
    s.stop();
#endif

    return ret;
}

