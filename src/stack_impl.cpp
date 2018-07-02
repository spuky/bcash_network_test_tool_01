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

#if (! defined _MSC_VER)
#include <sys/file.h>
#endif // _MSC_VER

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <random>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/address.hpp>
#include <coin/address_manager.hpp>
#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/block_merkle.hpp>
#include <coin/coins_cache.hpp>
#include <coin/db_env.hpp>
#include <coin/db_tx.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/http_transport.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/mining_manager.hpp>
#include <coin/nat_pmp_client.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/random.hpp>
#include <coin/rpc_json_parser.hpp>
#include <coin/rpc_manager.hpp>
#include <coin/script_checker_queue.hpp>
#include <coin/secret.hpp>
#include <coin/stack.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/transaction.hpp>
#include <coin/upnp_client.hpp>
#include <coin/version_bits.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>

using namespace coin;

/**
 * The main std::recursive_mutex.
 */
std::recursive_mutex stack_impl::g_mutex;

std::shared_ptr<db_env> stack_impl::g_db_env;
block_index * stack_impl::g_block_index_genesis = 0;
block_index * stack_impl::g_block_index_best = 0;
big_number stack_impl::g_best_chain_trust(0);
big_number stack_impl::g_best_invalid_trust;

stack_impl::stack_impl(coin::stack & owner)
    : stack_(owner)
    , strand_network_(io_service_network_)
    , timer_status_block_(globals::instance().io_service())
    , timer_status_wallet_(globals::instance().io_service())
    , timer_status_blockchain_(globals::instance().io_service())
    , timer_database_env_(globals::instance().io_service())
    , timer_block_merkles_save_(globals::instance().io_service())
    , timer_peer_headers_first_(io_service_network_)
    , time_last_peer_block_header_(std::time(0) - 600)
{
    // ...
}

void stack_impl::start()
{    
    if (
        m_configuration.args().count("mode") > 0 &&
        m_configuration.args()["mode"] == "spv"
        )
    {
        /**
         * Set that we are a client node.
         */
        globals::instance().set_operation_mode(
            coin::protocol::operation_mode_client
        );
        
        /**
         * Set that we are operating in (SPV) client mode.
         */
        globals::instance().set_client_spv(true);
    }
    
    if (m_configuration.args().count("bundle-id") > 0)
    {
    	/**
         * Override the filesystem::g_bundle_id (file directory name).
         */
    	auto bundle_id = m_configuration.args()["bundle-id"];
     
     	if (bundle_id.size() > 0)
      	{
    		filesystem::g_bundle_id = bundle_id;
    	}
    }

    try
    {
        create_directories();
    }
    catch (std::exception & e)
    {
        log_error(
            "Stack failed to create directories, what = " << e.what() << "."
        );
    }

    /**
     * Make sure only a single instance per directory is allowed.
     */
    lock_file_or_exit();
    
    /**
     * Backup the last wallet file deleting the oldest.
     */
    backup_last_wallet_file();

    /**
     * Set the state to starting.
     */
    globals::instance().set_state(globals::state_starting);
    
    /**
     * Load the configuration.
     */
    if (m_configuration.load() == false)
    {
        /**
         * If loading the configuration from disk failed then try to save it.
         */
        if (m_configuration.save() == false)
        {
            throw std::runtime_error(
                "Stack failed saving configuration to disk."
            );
        }
        else
        {
            log_info("Stack saved configuration to disk.");
        }
    }
    else
    {
        log_info("Stack loaded configuration from disk.");
    }
    
    /**
     * If the network TCP port is set to either the default or 0 we
     * randomize it.
     */
    if (
        m_configuration.network_port_tcp() == protocol::default_tcp_port
        )
    {
        /**
         * Set the TCP port to zero (random).
         */
        m_configuration.set_network_port_tcp(0);
        
        /**
         * Save the configuration file.
         */
        m_configuration.save();
    }
    
    /**
     * Set the globals transaction fee to that from the configuration.
     */
    globals::instance().set_transaction_fee(
        m_configuration.wallet_transaction_fee()
    );
    
    log_info(
        "Stack set configured transaction fee to " <<
        static_cast<double> (globals::instance().transaction_fee()) /
        constants::coin << "."
    );
    
    /**
     * Enforce an 8 KB/s read minimum.
     */
    std::size_t read = std::max(
        static_cast<std::size_t> (8192),
        m_configuration.network_tcp_read_maximum()
    );
    
    /**
     * Enforce an 8 KB/s write minimum.
     */
    std::size_t write = std::max(
        static_cast<std::size_t> (8192),
        m_configuration.network_tcp_write_maximum()
    );

    log_info(
        "Stack set networktcpbandwidthmaximum, read = " <<
        read << " bytes, write = " << write << " bytes."
    );
    
    /**
     * Set the network TCP read maximum.
     */
    m_configuration.set_network_tcp_read_maximum(read);
    
    /**
     * Set the network TCP write maximum.
     */
    m_configuration.set_network_tcp_write_maximum(write);
    
    /**
     * Set the read time per token.
     */
    tcp_transport::token_bucket_read().set_time_per_token(read);
    
    /**
     * Set the read burst per token (200%).
     */
    tcp_transport::token_bucket_read().set_time_per_burst(read * 2);
    
    /**
     * Set the write time per token.
     */
    tcp_transport::token_bucket_write().set_time_per_token(write);
    
    /**
     * Set the write burst per token (200%).
     */
    tcp_transport::token_bucket_write().set_time_per_burst(write * 2);
    
    /**
     * Reset the boost::asio::io_service.
     */
    globals::instance().io_service().reset();
    
    /**
     * Allocate the boost::asio::io_service::work.
     */
    work_.reset(new boost::asio::io_service::work(
        globals::instance().io_service())
    );
    
    /**
     * Allocate the boost::asio::io_service::work.
     */
    work_network_.reset(new boost::asio::io_service::work(
        io_service_network_)
    );

    /**
     * Allocate the thread.
     */
    auto thread = std::make_shared<std::thread> (
        std::bind(&stack_impl::loop, this)
    );
    
    /**
     * Retain the thread.
     */
    threads_.push_back(thread);

    /**
     * Allocate the db_env.
     */
    g_db_env.reset(new db_env());
    
    /**
     * Allocate the status manager.
     */
    m_status_manager.reset(new status_manager(*this));
    
    /**
     * Start the status manager.
     */
    m_status_manager->start();
    
    /**
     * Allocate the status.
     */
    std::map<std::string, std::string> status;
    
    /**
     * Set the status type.
     */
    status["type"] = "database";
    
    /**
     * Set the status value.
     */
    status["value"] = "Opening database environment";

    /**
     * Callback
     */
    m_status_manager->insert(status);
    
    /**
     * Set the globals::db_private.
     */
    if (globals::instance().is_client_spv() == true)
    {
        /**
         * (SPV) clients always use db_private.
         */
        m_configuration.set_db_private(true);
        
        /**
         * Save the configuration to disk.
         */
        m_configuration.save();

        globals::instance().set_db_private(m_configuration.db_private());
    }
    else
    {
        globals::instance().set_db_private(m_configuration.db_private());
    }
    
    /**
     * Get the database cache size.
     */
    auto database_cache_size = m_configuration.database_cache_size();
    
    /**
     * If we are an (SPV) client we only need 1 Megabyte of cache.
     */
    if (globals::instance().is_client_spv() == true)
    {
        if (database_cache_size > 1)
        {
            /**
             * Reset the database.cache_size to 1.
             */
            m_configuration.set_database_cache_size(1);
            
            /**
             * Save the configuration to disk.
             */
            m_configuration.save();
        
            database_cache_size = m_configuration.database_cache_size();
        }
    }
    
    /**
     * The BDB cache size to use.
     */
    auto database_cache_size_bdb = database_cache_size;
    
#if (defined USE_LEVELDB && USE_LEVELDB)
    /**
     * Set the leveldb cache size.
     */
    db_tx::set_leveldb_cache_size(database_cache_size);
    
	log_info("LevelDB cache size = " << database_cache_size << ".");

    /**
     * Set BDB to use an 1 Megabyte cache size.
     */
    database_cache_size_bdb = 1;
    
    /**
     * Open the coins cache (database).
     */
    if (globals::instance().is_client_spv() == false)
    {
		if (coins_cache::instance().open(database_cache_size) == false)
  		{
    		throw std::runtime_error("failed to open coins database");
    	}
    }
#endif // USE_LEVELDB

    /**
     * Open the db_env.
     */
    if (g_db_env->open(database_cache_size_bdb))
    {
        log_info("Stack is loading block index...");
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status type.
         */
        status["type"] = "database";
    
        /**
         * Set the status value.
         */
        status["value"] = "Loading index";

        /**
         * Callback
         */
        m_status_manager->insert(status);
        
        if (globals::instance().is_client_spv() == true)
        {
            globals::instance().io_service().post(
                globals::instance().strand().wrap(
                [this]()
            {
                std::uint8_t trys = 0;
                
                /**
                 * Load the block merkles from disk.
                 */
                spv_block_merkles_load(trys);
                
                if (trys > 1)
                {
                    log_info(
                        "Stack found no valid (SPV) chain files, "
                        "syncing from genesis."
                    );
                }
                
                /**
                 * If we are an SPV client set the last block received to that
                 * of the genesis block if we do not yet have any merkle blocks.
                 */
                if (globals::instance().spv_block_merkles().size() == 0)
                {
                    auto hash_genesis =
                        (constants::test_net ?
                        block::get_hash_genesis_test_net() :
                        block::get_hash_genesis())
                    ;
                    
                    globals::instance().spv_block_merkles()[hash_genesis].reset(
                        new block_merkle(block::create_genesis()))
                    ;
                    
                    globals::instance().set_spv_block_last(
                        *globals::instance().spv_block_merkles()[hash_genesis]
                    );
                }
                
                /**
                 * Starts the block_merkle's save timer.
                 */
                timer_block_merkles_save_.expires_from_now(
                    std::chrono::seconds(60 * 60)
                );
                timer_block_merkles_save_.async_wait(
                    globals::instance().strand().wrap(
                        [this](boost::system::error_code ec)
                        {
                            if (ec)
                            {
                                // ...
                            }
                            else
                            {
                                /**
                                 * Save the (SPV) block_merkle's to disk.
                                 */
                                spv_block_merkles_save();
                            }
                        }
                    )
                );
            }));
        }
        
        /**
         * Load the block index.
         */
        load_block_index([this] (const bool & success)
        {
            if (success == true)
            {
                log_info("Stack loaded index.");
                
                /**
                 * Allocate the status.
                 */
                std::map<std::string, std::string> status;

                /**
                 * Set the status type.
                 */
                status["type"] = "database";
    
                /**
                 * Set the status value.
                 */
                status["value"] = "Loaded index";

                /**
                 * Callback
                 */
                m_status_manager->insert(status);

				/**
 				 * If we have no (peer) block headers for synchronization set
                 * the genesis block header as the best.
                 */
                if (
                	globals::instance().peer_use_headers_first_chain_sync(
                    ) == true && globals::instance().peer_headers_first_blocks(
                    ).size() == 0
                    )
                {
                    auto hash_genesis =
                        (constants::test_net ?
                        block::get_hash_genesis_test_net() :
                        block::get_hash_genesis())
                    ;
                    
                    globals::instance().peer_headers_first_blocks()[
                    	hash_genesis].reset(new block(block::create_genesis()))
                    ;
                    
                    globals::instance().set_peer_headers_first_block_last(
                        *globals::instance().peer_headers_first_blocks()[
                        hash_genesis]
                    );
                    
                    /**
                     * Map the block header height to the hash.
                     */
                    globals::instance().peer_headers_first_heights_and_hashes()[
                        0] = hash_genesis
                    ;
                }

                /**
                 * Always use deterministic wallets in SPV mode.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    m_configuration.set_wallet_deterministic(true);
                }
                
                /**
                 * Check that the wallet.dat file exists.
                 */
                std::ifstream ifs(filesystem::data_path() + "/wallet.dat");
            
                auto exists = false;
                
                if (ifs.good() == true)
                {
                    if (g_db_env->verify("wallet.dat"))
                    {
                        log_info("Stack verified wallet.dat.");
                        
                        exists = true;
                    }
                    else
                    {
                        throw std::runtime_error(
                            "failed to verify wallet.dat."
                        );
                    }
                    
                    ifs.close();
                }
                else
                {
                    log_info("Stack is initializing wallet.dat.");
                    
                    exists = false;
                }
                
                /**
                 * Allocate the status.
                 */
                std::map<std::string, std::string> status2;
            
                /**
                 * Set the status type.
                 */
                status2["type"] = "wallet";

                /**
                 * Set the status value.
                 */
                status2["value"] = "Loading wallet";

                /**
                 * Callback
                 */
                m_status_manager->insert(status2);
                
                /**
                 * Load the wallet.
                 */
                load_wallet([this] (
                    const bool & first_run, const db_wallet::error_t & error
                    )
                {
                    if (error != db_wallet::error_load_ok)
                    {
                        if (error == db_wallet::error_corrupt)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Wallet is corrupted";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_noncritical_error)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet keys loaded correctly but "
                                "transaction or address book entries might be "
                                "missing or incorrect"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_too_new)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet requires a newer software version"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_need_rewrite)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet has been rewritten, please restart to "
                                "complete the process"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Wallet failed to load";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                    }
                    else
                    {
                        /**
                         * Allocate the status.
                         */
                        std::map<std::string, std::string> status;
                    
                        /**
                         * Set the status type.
                         */
                        status["type"] = "wallet";
    
                        /**
                         * Set the status value.
                         */
                        status["value"] = "Loaded wallet";

                        /**
                         * Callback
                         */
                        m_status_manager->insert(status);
                    }
                
                    /**
                     * -upgradewallet
                     */
                    
                    /**
                     * If this is the first run we need to create a wallet.
                     */
                    if (first_run)
                    {
						/**
						 * Get the db_wallet.
						 */
						db_wallet wallet_db("wallet.dat");

                       /**
                        * Set the creation timestamp.
                        */
                        globals::instance().wallet_main()->set_timestamp(
                            std::time(0)
                        );

                        /**
                         * Write the creation timestamp.
                         */
                        wallet_db.write_timestamp(std::time(0));
                        
						/**
                         * Use the latest wallet features for new wallets.
                         */
                        globals::instance().wallet_main()->set_min_version(
                            wallet::feature_latest, &wallet_db
                        );

                        /**
                         * Seed RNG.
                         */
                        std::srand(static_cast<std::uint32_t> (std::clock()));

                        /**
                         * If we got the argument wallet-seed we need to make
                         * sure to set the wallet.deterministric to true
                         * in the configuration if it is false.
                         */
                        if (m_configuration.args().count("wallet-seed") > 0)
                        {
                            /**
                             * If the configuration wallet.deterministic is
                             * false set it to true and save the
                             * configuration.
                             */
                            if (
                                m_configuration.wallet_deterministic(
                                ) == false
                                )
                            {
                                /**
                                 * Set the wallet.deterministic to true.
                                 */
                                m_configuration.set_wallet_deterministic(
                                    true
                                );
                                
                                /**
                                 * Save the configuration.
                                 */
                                m_configuration.save();
                            }
                        }
                        
                        if (
                            m_configuration.wallet_deterministic() == true &&
                            globals::instance().wallet_main(
                            )->get_hd_configuration().id_key_master(
                            ).is_empty() == true
                            )
                        {
                            key k;

                            /**
                             * If we have the wallet-seed param restore the
                             * HD key master from it, otherwise generate a new
                             * HD key master.
                             */
                            if (m_configuration.args().count("wallet-seed") > 0)
                            {
                                /**
                                 * Since we are restoring set the wallet
                                 * timestamp to 182 days ago.
                                 * @note The "rescan date" needs to be
                                 * configurable and these two lines can be
                                 * removed.
                                 */
                                globals::instance().wallet_main()->set_timestamp(
                                    std::time(0) - 182 * 24 * 60 * 60)
                                ;
                                db_wallet("wallet.dat").write_timestamp(
                                    std::time(0) - 182 * 24 * 60 * 60
                                );
                        
                                auto wallet_seed =
                                    m_configuration.args()["wallet-seed"]
                                ;
                                
                                /**
                                 * Rescan the chain once the io_service has
                                 * started.
                                 */
                                rescan_chain(0);
                                
                                /**
                                 * Clear the wallet-seed from memory.
                                 */
                                m_configuration.args().erase("wallet-seed");
                                
                                /**
                                 * Allocate an empty private key.
                                 */
                                key::secret_t secret;
            
                                secret = utility::from_hex(wallet_seed);
                                
                                try
                                {
                                    k.set_secret(secret, true);
                                }
                                catch (std::exception & e)
                                {
                                    log_error(
                                        "Stack, failed to restore wallet, "
                                        "invalid seed, what = " <<
                                        e.what() << "."
                                    );

                                    std::abort();
                                }
                                
                                assert(k.is_valid());
                                
                                if (k.is_valid() == false)
                                {
                                    log_error(
                                        "Stack, failed to restore wallet, "
                                        "invalid seed."
                                    );
                                    
                                    std::abort();
                                }
                            }
                            else
                            {
                                k.make_new_key(true);
                            }
                            
                            if (
                                globals::instance().wallet_main(
                                )->set_hd_key_master(k) == false
                                )
                            {
                                throw std::runtime_error(
                                    "stack_impl::start(): Set key HD "
                                    "master failed"
                                );
                            }
                        }
        
                        /**
                         * Allocate a new public key.
                         */
                        key_public key_default;
                        
                        if (
                            globals::instance().wallet_main()->get_key_from_pool(
                            key_default, false) == false
                            )
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Failed to initialize key pool";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        
                        /**
                         * Set the main wallet's default public key.
                         */
                        globals::instance().wallet_main()->set_key_public_default(
                            key_default, true
                        );
                        
                        if (
                            globals::instance().wallet_main()->set_address_book_name(
                            globals::instance().wallet_main()->key_public_default(
                            ).get_id(), "") == false
                            )
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet failed to set default address"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else
                        {
                            globals::instance().io_service().post(
                                globals::instance().strand().wrap([this]()
                            {
                                /**
                                 * Backup the new wallet.
                                 */
                                db_wallet::backup(
                                    *globals::instance().wallet_main(),
                                    filesystem::data_path() + "backups/"
                                );
                            }));
                        }
                    }
                    
                    if (m_configuration.wallet_deterministic() == true)
                    {
                        if (
                            globals::instance().wallet_main(
                            )->get_hd_configuration().id_key_master(
                            ).is_empty() == true
                            )
                        {
                            log_warn(
                                "Stack, normal wallets cannot be converted to "
                                "hd wallets. To create an hd wallet you must "
                                "first remove the normal wallet."
                            );
                            
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet failed to initialize, refer to log file"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);

                            exit(0);
                        }
                    }
                    else
                    {
                        if (
                            globals::instance().wallet_main(
                            )->get_hd_configuration().id_key_master(
                            ).is_empty() == false
                            )
                        {
                            log_warn(
                                "Stack, hd wallets cannot be converted to "
                                "normal wallets. To create a normal wallet "
                                "you must first remove the hd wallet."
                            );
                            
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet failed to initialize, refer to log file"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                            
                            exit(0);
                        }
                    }

                    log_info(
                        "Stack, wallet default address = " <<
                        address(globals::instance().wallet_main(
                        )->key_public_default().get_id()).to_string() << "."
                    );
                    
                    /**
                     * Register the main wallet.
                     */
                    wallet_manager::instance().register_wallet(
                        globals::instance().wallet_main()
                    );
                    
                    /**
                     * If the wallet has no timestamp set it to 182 days ago.
                     * @note This can be removed once the timestamp is
                     * set during wallet creation after some time deployed.
                     */
                    if (globals::instance().wallet_main()->timestamp() == 0)
                    {
                        globals::instance().wallet_main()->set_timestamp(
                            std::time(0) - 182 * 24 * 60 * 60)
                        ;
                        db_wallet("wallet.dat").write_timestamp(
                            std::time(0) - 182 * 24 * 60 * 60
                        );
                    }
                    
                    log_info(
                        "Stack, wallet timestamp is " <<
                        globals::instance().wallet_main()->timestamp() << "."
                    );

                    /**
                     * If we are an (SPV) client perform any initialization.
                     */
                    if (globals::instance().is_client_spv() == true)
                    {
                        globals::instance().set_spv_time_wallet_created(
                            globals::instance().wallet_main()->timestamp()
                        );
                        globals::instance().spv_reset_bloom_filter();
                    }
                    
                    /**
                     * Thin clients (SPV) do not keep a block index.
                     */
                    if (globals::instance().is_client_spv() == false)
                    {
                        log_info(
                            "Stack, block indexes = " <<
                            globals::instance().block_indexes().size() <<
                            ", best block height = " <<
                            globals::instance().best_block_height() <<
                            ", best block hash = " <<
                            stack_impl::get_block_index_best(
                            )->get_block_hash().to_string() <<
                            ", key pool size = " <<
                            globals::instance().wallet_main(
                            )->get_key_pool().size()
                            << ", wallet transactions = " <<
                            globals::instance().wallet_main(
                            )->transactions().size()
                            << ", address book entries = " <<
                            globals::instance().wallet_main(
                            )->address_book().size()
                            << "."
                        );
                    }
                    else
                    {
                        log_info(
                            "Stack, key pool size = " <<
                            globals::instance().wallet_main(
                            )->get_key_pool().size()
                            << ", wallet transactions = " <<
                            globals::instance().wallet_main(
                            )->transactions().size()
                            << ", address book entries = " <<
                            globals::instance().wallet_main(
                            )->address_book().size()
                            << "."
                        );
                    }
    
                    /**
                     * Allocate the status.
                     */
                    std::map<std::string, std::string> status;
                    
                    /**
                     * Set the status type.
                     */
                    status["type"] = "wallet";

                    /**
                     * Set the status value.
                     */
                    status["value"] = "address";
    
                    /**
                     * Set the wallet.address.
                     */
                    status["wallet.address"] =
                        address(globals::instance().wallet_main(
                        )->key_public_default().get_id()).to_string()
                    ;

                    /**
                     * Callback
                     */
                    m_status_manager->insert(status);

                    auto args = m_configuration.args();

                    /**
                     * Check for erase-wallet-transactions.
                     */
                    auto it1 = args.find("erase-wallet-transactions");

                    if (it1 != args.end())
                    {
                        log_info("Stack is erasing wallet transactions.");
                        
                        /**
                         * Erase transactions.
                         */
                        globals::instance().wallet_main()->erase_transactions();
                        
                        /**
                         * Flush the wallet.
                         */
                        globals::instance().wallet_main()->flush();
                    }

                    /**
                     * Callback all transactions from the main wallet.
                     */
                    for (
                        auto & i :
                        globals::instance().wallet_main()->transactions()
                        )
                    {
                        /**
                         * Do not inform the status_manager of transactions
                         * greater than N days.
                         */
                        if (
                            std::time(0) - i.second.time() >
                            m_configuration.wallet_transaction_history_maximum()
                            )
                        {
                            continue;
                        }
                        
                        if (i.second.is_coin_base())
                        {
                            /**
                             * Only callback generated/mined transactions
                             * at depth 1.
                             */
                            if (i.second.is_in_main_chain() == false)
                            {
                                continue;
                            }
                        }
    
                        /**
                         * Allocate the info.
                         */
                        std::map<std::string, std::string> status;

                        /**
                         * Add the transaction_wallet values to the status.
                         */
                        for (auto & j : i.second.values())
                        {
                            status[j.first] = j.second;
                        }

                        /**
                         * Set the type.
                         */
                        status["type"] = "wallet.transaction";

                        /**
                         * Set the value.
                         */
                        status["value"] = "updated";
                        
                        /**
                         * Set the wallet.transaction.hash.
                         */
                        status["wallet.transaction.hash"] =
                            i.second.get_hash().to_string()
                        ;
                        
                        /**
                         * Set the wallet.transaction.in_main_chain.
                         */
                        status["wallet.transaction.in_main_chain"] =
                            std::to_string(i.second.is_in_main_chain())
                        ;
                        
                        /**
                         * Set the wallet.transaction.is_from_me.
                         */
                        status["wallet.transaction.is_from_me"] =
                            std::to_string(i.second.is_from_me())
                        ;

                        /**
                         * Set the wallet.transaction.confirmations.
                         */
                        status["wallet.transaction.confirmations"] =
                            std::to_string(i.second.get_depth_in_main_chain())
                        ;
                        
                        /**
                         * Set the wallet.transaction.spv_block_height.
                         */
                        status["wallet.transaction.spv_block_height"] =
                            std::to_string(i.second.spv_block_height())
                        ;
                        
                        /**
                         * Set the wallet.transaction.confirmed.
                         */
                        status["wallet.transaction.confirmed"] =
                            std::to_string(i.second.is_confirmed())
                        ;
                        
                        /**
                         * Set the wallet.transaction.credit.
                         */
                        status["wallet.transaction.credit"] =
                            std::to_string(i.second.get_credit(true))
                        ;
                        
                        /**
                         * Set the wallet.transaction.debit.
                         */
                        status["wallet.transaction.debit"] =
                            std::to_string(i.second.get_debit())
                        ;
                        
                        /**
                         * Set the wallet.transaction.net.
                         */
                        status["wallet.transaction.net"] =
                            std::to_string(i.second.get_credit(true) -
                            i.second.get_debit())
                        ;
                        
                        /**
                         * Set the wallet.transaction.time.
                         */
                        status["wallet.transaction.time"] = std::to_string(
                            i.second.time()
                        );
                        
                        if (i.second.is_coin_base())
                        {
                            /**
                             * Set the wallet.transaction.coin_base.
                             */
                            status["wallet.transaction.coin_base"] = "1";
                            
                            std::int64_t credit = 0;
                            
                            /**
                             * Since this is a coin base transaction we only
                             * add the first value from the first transaction
                             * out.
                             */
                            for (auto & j : i.second.transactions_out())
                            {
                                if (
                                    globals::instance().wallet_main(
                                    )->is_mine(j)
                                    )
                                {
                                    credit += j.value();
                                    
                                    break;
                                }
                            }
                            
                            /**
                             * Set the wallet.transaction.credit.
                             */
                            status["wallet.transaction.credit"] =
                                std::to_string(credit)
                            ;
                            
                            /**
                             * Set the wallet.transaction.type.
                             */
                            status["wallet.transaction.type"] = "mined";
                        }
                    
                        /**
                         * Callback on new or updated transaction.
                         */
                        m_status_manager->insert(status);
                    }
            
                    auto index_rescan = stack_impl::get_block_index_best();

                    /**
                     * Check for erase-wallet-transactions.
                     */
                    auto it2 = args.find("erase-wallet-transactions");

                    if (it2 != args.end())
                    {
                        index_rescan = stack_impl::get_block_index_genesis();
                    }
                    else
                    {
                        /**
                         * If the configuration is set to rescan the wallet
                         * we set it to false again and set the globals option
                         * to perform the rescan.
                         */
                        if (m_configuration.wallet_rescan() == true)
                        {
                            m_configuration.set_wallet_rescan(false);
                            
                            m_configuration.save();
                            
                            globals::instance().set_option_rescan(true);
                        }

                        if (globals::instance().option_rescan() == true)
                        {
                            index_rescan =
                                stack_impl::get_block_index_genesis()
                            ;
                        }
                        else
                        {
                            db_wallet wallet_db("wallet.dat");
                            
                            block_locator locator;
                            
                            if (wallet_db.read_bestblock(locator))
                            {
                                index_rescan = locator.get_block_index();
                            }
                        }
                    }

                    if (
                        stack_impl::get_block_index_best() !=
                        index_rescan && stack_impl::get_block_index_best() &&
                        index_rescan &&
                        stack_impl::get_block_index_best()->height() >
                        index_rescan->height()
                        )
                    {
                        log_debug("Stack, rescanning wallet for transactions.");

                        /**
                         * Allocate the status.
                         */
                        std::map<std::string, std::string> status;
                        
                        /**
                         * Set the status type.
                         */
                        status["type"] = "wallet";
    
                        /**
                         * Set the status value.
                         */
                        status["value"] = "Rescanning wallet";
                        
                        /**
                         * Set the status wallet.status.
                         */
                        status["wallet.status"] = "Rescanning wallet";

                        /**
                         * Callback
                         */
                        m_status_manager->insert(status);

                        log_info(
                            "Stack, wallet is rescanning last " <<
                            stack_impl::get_block_index_best()->height() -
                            index_rescan->height() <<
                            " blocks from block " << index_rescan->height() <<
                            "."
                        );
                    
                        /**
                         * Rescan the blockchain for transactions.
                         */
                        globals::instance().wallet_main()->scan_for_transactions(
                            index_rescan, true
                        );
                    }
                });

                /**
                 * Get the number of cores.
                 */
                auto cores = 0;
                
                /**
                 * The main IO runs on a single thread with as many child
                 * threads as needed to perform computational work.
                 */
                if (false)
                {
                    cores = std::thread::hardware_concurrency();

                    /**
                     * Do not use more than 8 cores.
                     */
                    if (cores >= 8)
                    {
                        cores = 8;
                    }
                }

                log_info("Stack is adding " << cores << " threads.");
                
                for (auto i = 0; i < cores; i++)
                {
                    auto thread = std::make_shared<std::thread> (
                        std::bind(&stack_impl::loop, this)
                    );
                    
                    /**
                     * Retain the thread.
                     */
                    threads_.push_back(thread);
                }
                
                auto thread = std::make_shared<std::thread> (
                    std::bind(&stack_impl::loop_network, this)
                );
                
                /**
                 * Retain the thread.
                 */
                threads_.push_back(thread);
            }
            else
            {
                log_info("Stack failed to load block index.");
                
                /**
                 * Allocate the error.
                 */
                std::map<std::string, std::string> error;
                
                /**
                 * Set the error type.
                 */
                error["type"] = "database";
                
                /**
                 * Set the error value.
                 */
                error["value"] = "Failed to load blkindex.dat";

                /**
                 * Callback
                 */
                on_error(error);
            }
        });
    }
    else
    {
        /**
         * Allocate the error.
         */
        std::map<std::string, std::string> error;
        
        /**
         * Set the error type.
         */
        error["type"] = "database";
        
        /**
         * Set the error value.
         */
        error["value"] =
            "Failed to initialize database environment. Backup " +
            filesystem::data_path() + " and remove everything except for "
            "wallet.dat" + "."
        ;

        /**
         * Callback
         */
        on_error(error);
    }
    
    /**
     * The minimum disk space required (50 Megabytes).
     */
    const std::uint64_t minimum_disk_space = 52428800;

    /**
     * Get the available disk space.
     */
    auto disk_info = utility::disk_info(filesystem::data_path());
    
    log_debug("Stack, disk info.space = " << disk_info.available << ".");
    
    if (disk_info.available < minimum_disk_space)
    {
        /**
         * Allocate the error.
         */
        std::map<std::string, std::string> error;
        
        /**
         * Set the error type.
         */
        error["type"] = "disk";
        
        /**
         * Set the error value.
         */
        error["value"] = "Disk space is too low";

        /**
         * Callback
         */
        on_error(error);
    }

    /**
     * Check if we need to export the blockchain.dat file to disk.
     */
    if (
        m_configuration.args().count("export-blockchain") > 0 &&
        m_configuration.args()["export-blockchain"] == "1"
        )
    {
        globals::instance().io_service().post(
            globals::instance().strand().wrap([this]()
        {
            if (export_blockchain_file() == true)
            {
                log_info("Stack exported blockchain file(s).");
            }
            else
            {
                log_error("Stack failed to export blockchain file(s).");
            }
        }));
    }
    
    /**
     * Check if we need to import the blockchain.dat file from disk.
     */
    if (
        m_configuration.args().count("import-blockchain") > 0 &&
        m_configuration.args()["import-blockchain"] == "1"
        )
    {
        globals::instance().io_service().post(
            globals::instance().strand().wrap([this]()
        {
            /**
             * Import blockchain.dat from disk.
             */
            auto path = filesystem::data_path() + "blockchain.dat";
        
            if (import_blockchain_file(path) == true)
            {
                log_info("Stack imported blockchain file.");
            }
            else
            {
                log_error("Stack failed to import blockchain file.");
            }
        }));
    }

    globals::instance().io_service().post(
        globals::instance().strand().wrap([this]()
    {
        /**
         * If stop was previously called then don't proceed.
         */
        if (globals::instance().state() >= globals::state_stopping)
        {
            return;
        }
        
        /**
         * Get the configured TCP port.
         */
        auto tcp_port = m_configuration.network_port_tcp();
    
        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Add wallet transactions that aren't already in a block to the
             * transactions.
             */
            globals::instance().wallet_main()->reaccept_wallet_transactions();
    
            /**
             * Allocate the tcp_acceptor.
             */
            m_tcp_acceptor.reset(
                new tcp_acceptor(io_service_network_, strand_network_)
            );
            
            /**
             * Set the accept handler.
             */
            m_tcp_acceptor->set_on_accept(
                [this] (std::shared_ptr<tcp_transport> transport)
                {
                    /**
                     * Inform the tcp_connection_manager.
                     */
                    m_tcp_connection_manager->handle_accept(transport);
                }
            );
            
            /**
             * If we are on a test network force the local port to the test
             * network port.
             */
            if (constants::test_net == true)
            {
            	tcp_port = protocol::default_tcp_port_testnet;
            }

            /**
             * If the port is zero generate a random one.
             */
            if (tcp_port == 0)
            {
                /**
                 * Get a random ephemeral port.
                 */
                tcp_port = random::uint16_random_range(32768, 61000);
                
                /**
                 * Set the network port.
                 */
                m_configuration.set_network_port_tcp(tcp_port);
                
                /**
                 * Save the confiuration.
                 */
                m_configuration.save();
            }
            
            auto ret = false;
            
            while (ret == false)
            {
                ret = m_tcp_acceptor->open(tcp_port);
                
                if (ret == false)
                {
                    tcp_port += 2;
                }
                else
                {
                    /**
                     * Set the network tcp port.
                     */
                    m_configuration.set_network_port_tcp(tcp_port);
                    
                    /**
                     * Save the configuration.
                     */
                    m_configuration.save();
                    
                    break;
                }
                
                /**
                 * Try 50 even ports before giving up.
                 */
                if (tcp_port > m_configuration.network_port_tcp() + 100)
                {
                    break;
                }
            }
            
            if (ret == false)
            {
                throw std::runtime_error("failed to start tcp_acceptor");
            }
            
            assert(m_tcp_acceptor->local_endpoint().port() == tcp_port);
            
            /**
             * Set the local endpoint.
             */
            m_local_endpoint = m_tcp_acceptor->local_endpoint();

            log_info(
                "TCP Acceptor started, local endpoint = " <<
                m_local_endpoint << "."
            );
        }
      
        /**
         * Set the nonce used in the version message.
         */
        globals::instance().set_version_nonce(random::uint64());

        log_info(
            "Stack generated version nonce = " <<
            globals::instance().version_nonce() << "."
        );

        /**
         * Allocate the address_manager.
         */
        m_address_manager.reset(
            new address_manager(globals::instance().io_service(),
            globals::instance().strand(), *this)
        );
        
        /**
         * Allocate the tcp_connection_manager.
         */
        m_tcp_connection_manager.reset(
            new tcp_connection_manager(globals::instance().io_service(),
            *this)
        );
        
        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Allocate the nat_pmp_client.
             */
            m_nat_pmp_client.reset(
                new nat_pmp_client(globals::instance().io_service())
            );
            
            /**
             * Start the nat_pmp_client.
             */
            m_nat_pmp_client->start();
        }

        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Allocate the rpc_manager.
             */
            m_rpc_manager.reset(
                new rpc_manager(globals::instance().io_service(),
                globals::instance().strand(), *this)
            );

            /**
             * Start the rpc_manager.
             */
            m_rpc_manager->start();
        }

        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Allocate the upnp_client.
             */
            m_upnp_client.reset(new upnp_client(
                globals::instance().io_service(),
                globals::instance().strand())
            );
            
            /**
             * Start the upnp_client.
             */
            m_upnp_client->start();
        }
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status type.
         */
        status["type"] = "network";

        /**
         * Set the status value.
         */
        status["value"] = "Loading network addresses";

        /**
         * Callback
         */
        m_status_manager->insert(status);
        
        /**
         * Start the address_manager.
         */
        m_address_manager->start();
        
        /**
         * Set the status type.
         */
        status["type"] = "network";

        /**
         * Set the status value.
         */
        status["value"] = "Loaded network addresses";

        /**
         * Callback
         */
        m_status_manager->insert(status);
        
        /**
         * Start the tcp_connection_manager.
         */
        m_tcp_connection_manager->start();
        
        /**
         * Start the script_checker_queue.
         */
        if (globals::instance().is_client_spv() == false)
        {
            script_checker_queue::instance().start();
        }
        
        /**
         * Set the status type.
         */
        status["type"] = "network";

        /**
         * Set the status value.
         */
        status["value"] = "Connecting";

        /**
         * Callback
         */
        m_status_manager->insert(status);
        
        /**
         * Starts the block status timer.
         */
        timer_status_block_.expires_from_now(std::chrono::seconds(1));
        timer_status_block_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_status_block();
                    }
                }
            )
        );
        
        /**
         * Starts the wallet status timer.
         */
        timer_status_wallet_.expires_from_now(std::chrono::seconds(1));
        timer_status_wallet_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_status_wallet();
                    }
                }
            )
        );
        
        /**
         * Starts the status blockchain timer.
         */
        timer_status_blockchain_.expires_from_now(std::chrono::seconds(8));
        timer_status_blockchain_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_status_blockchain();
                    }
                }
            )
        );
        
        /**
         * Starts the database environment timer.
         */
        timer_database_env_.expires_from_now(std::chrono::seconds(8));
        timer_database_env_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_database_env();
                    }
                }
            )
        );
        
        if (globals::instance().peer_use_headers_first_chain_sync() == true)
        {
            /**
             * Starts the (peer) block headers first synchronization timer.
             */
            timer_peer_headers_first_.expires_from_now(
            	std::chrono::seconds(8)
            );
            timer_peer_headers_first_.async_wait(
                strand_network_.wrap(
                    [this](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            on_peer_headers_first();
                        }
                    }
                )
            );
		}
        
        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Allocate the mining_manager.
             */
            m_mining_manager.reset(
                new mining_manager(globals::instance().io_service(), *this)
            );
            
            /**
             * Start the mining manager.
             */
            m_mining_manager->start();
        }
        
        /**
         * Add port mappings by posting to the boost::asio::io_service to
         * induce a slight delay.
         */
        globals::instance().io_service().post(
            globals::instance().strand().wrap([this, tcp_port]()
        {
            if (globals::instance().is_client_spv() == false)
            {
                /**
                 * Add a mapping for our TCP port.
                 */
                m_nat_pmp_client->add_mapping(
                    nat_pmp::protocol_tcp, tcp_port
                );
            
                /**
                 * Add a mapping for our UDP port.
                 */
                m_nat_pmp_client->add_mapping(
                    nat_pmp::protocol_udp, tcp_port
                );
                
                /**
                 * Add a mapping for our TCP port.
                 */
                m_upnp_client->add_mapping(
                    upnp_client::protocol_tcp, tcp_port
                );
                
                /**
                 * Add a mapping for our UDP port.
                 */
                m_upnp_client->add_mapping(
                    upnp_client::protocol_udp, tcp_port
                );
            }
            
            /**
             * Download centrally hosted bootstrap peers.
             */
            do_check_peers(0);
        }));
    }));
    
    /**
     * Set the state to started.
     */
    globals::instance().set_state(globals::state_started);
}

void stack_impl::stop()
{
	log_info("Stack is stopping...");
    
    /**
     * Set the state to stopping.
     */
    globals::instance().set_state(globals::state_stopping);
    
    /**
     * Lock the main std::recursive_mutex while stopping objects but unlock
     * it (scoped) afterwards.
	 */
	{
        /**
         * Lock the main std::recursive_mutex.
         */
        std::lock_guard<std::recursive_mutex> l1(g_mutex);
        
        /**
         * Save the configuration to disk.
         */
        if (m_configuration.save() == false)
        {
            log_error("Stack failed to save configuration to disk.");
        }

        if (globals::instance().is_client_spv() == true)
        {
            /**
             * Save the last block_merkle's to disk.
             */
            spv_block_merkles_save();
        }
        
        /**
         * If we are operating in (peer) headers first chain synchronization
         * mode cancel the timer_peer_headers_first_.
         */
        if (globals::instance().peer_use_headers_first_chain_sync() == true)
        {
            timer_peer_headers_first_.cancel();
        }
        
        /**
         * Stop the mining_manager.
         */
        if (m_mining_manager)
        {
            m_mining_manager->stop();
        }
        
        /**
         * Stop the tcp_acceptor.
         */
        if (m_tcp_acceptor)
        {
            m_tcp_acceptor->close();
        }
        
        /**
         * Stop the address_manager.
         */
        if (m_address_manager)
        {
            m_address_manager->stop();
        }
        
        /**
         * Stop the tcp_connection_manager.
         */
        if (m_tcp_connection_manager)
        {
            m_tcp_connection_manager->stop();
        }
        
        /**
         * Stop the nat_pmp_client.
         */
        if (m_nat_pmp_client)
        {
            m_nat_pmp_client->stop();
        }
        
        /**
         * Stop the nat_pmp_client.
         */
        if (m_rpc_manager)
        {
            m_rpc_manager->stop();
        }
        
        /**
         * Stop the upnp_client.
         */
        if (m_upnp_client)
        {
            m_upnp_client->stop();
        }
        
        /**
         * Stop the status_manager.
         */
        if (m_status_manager)
        {
            m_status_manager->stop();
        }
    }
    
    /**
     * Stop the script_checker_queue.
     */
    if (globals::instance().is_client_spv() == false)
    {
        script_checker_queue::instance().stop();
    }
    
    /**
     * Unregister the main wallet.
     */
    wallet_manager::instance().unregister_wallet(
        globals::instance().wallet_main()
    );
    
    /**
     * Cancel the block status timer.
     */
    timer_status_block_.cancel();
    
    /**
     * Cancel the wallet status timer.
     */
    timer_status_wallet_.cancel();
    
    /**
     * Cancel the blockchain status timer.
     */
    timer_status_blockchain_.cancel();
    
    /**
     * Cancel the database environment timer.
     */
    timer_database_env_.cancel();
    
    /**
     * Cancel the block_merkle's save timer.
     */
    timer_block_merkles_save_.cancel();
    

    /**
     * Stop the netowrk boost::asio::io_service.
     */
    io_service_network_.stop();
    
    /**
     * Stop the main boost::asio::io_service.
     */
    globals::instance().io_service().stop();
    
    /**
     * Reset the main work.
     */
    work_.reset();
    
    /**
     * Reset the network work.
     */
    work_network_.reset();
    
    /**
     * Join the threads.
     */
    for (auto & i : threads_)
    {
        try
        {
            if (i->joinable())
            {
                i->join();
            }
        }
        catch (std::exception & e)
        {
            // ...
        }
    }

    /**
     * Detach the block_index objects from each other.
     */
    for (auto & i : globals::instance().block_indexes())
    {
        /**
         * Set the previous block index to null.
         */
        if (i.second)
        {
            delete i.second;
        }
    }

#if (defined USE_LEVELDB && USE_LEVELDB)
	db_tx::leveldb_close();
	
    /**
     * Close the coins database.
     */
    if (globals::instance().is_client_spv() == false)
    {
        coins_cache::instance().close();
    }
#endif // USE_LEVELDB

    /**
     * Flush the db_env.
     */
    if (g_db_env)
    {
        g_db_env->flush();
    }
    
    /**
     * Close the db_env.
     */
    if (g_db_env)
    {
        g_db_env->close_DbEnv();
    }
    
    /**
     * Clear the threads.
     */
    threads_.clear();
    
    /**
     * Reset
     */
    m_address_manager.reset();
    
    /**
     * Reset
     */
    m_mining_manager.reset();
    
    /**
     * Reset
     */
    m_tcp_acceptor.reset();
    
    /**
     * Reset
     */
    m_tcp_connection_manager.reset();
    
    /**
     * Reset
     */
    m_nat_pmp_client.reset();
    
    /**
     * Reset
     */
    m_status_manager.reset();
    
    /**
     * Reset
     */
    g_db_env.reset();
    
    /**
     * Reset globals.
     */
    globals::instance().block_indexes().clear();
    globals::instance().set_wallet_main(std::shared_ptr<wallet> ());
    globals::instance().orphan_blocks().clear();
    globals::instance().orphan_transactions().clear();
    globals::instance().orphan_blocks_by_previous().clear();
    globals::instance().orphan_transactions_by_previous().clear();
    globals::instance().relay_invs().clear();
    globals::instance().relay_inv_expirations().clear();
    g_block_index_genesis = 0;
    g_block_index_best = 0;
    
    /**
     * Set the state to stopped.
     */
    globals::instance().set_state(globals::state_stopped);
    
    log_info("Stack has stopped.");
}

void stack_impl::connect()
{
    if (m_tcp_connection_manager)
    {
        m_tcp_connection_manager->connect();
    }
}

void stack_impl::disconnect()
{
    if (m_tcp_connection_manager)
    {
        m_tcp_connection_manager->disconnect();
    }
}

void stack_impl::send_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, amount, destination, wallet_values]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "transaction";
        
        address addr(destination);
        
        bool perform_send = true;
        
        if (addr.is_valid() == false)
        {
            log_error("Stack, send coins failed, invalid destination address.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "invalid destination address";
        }

        if (amount < constants::min_txout_amount)
        {
            log_error("Stack, send coins failed, amount too small.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "amount too small";
        }
        
        if (
            amount + globals::instance().transaction_fee() >
            globals::instance().wallet_main()->get_balance()
            )
        {
            log_error("Stack, send coins failed, insufficient funds.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "insufficient funds";
        }
        
        if (globals::instance().wallet_main()->is_locked())
        {
            log_error("Stack, send coins failed, wallet is locked.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "wallet is locked";
        }
        
        if (m_tcp_connection_manager->is_connected() == false)
        {
            log_error("Stack, send coins failed, not connected to network.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "not connected to network";
        }
        
        if (perform_send)
        {
            /**
             * Allocate the transaction_wallet.
             */
            transaction_wallet wtx(globals::instance().wallet_main().get());
            
            /**
             * Check for a comment.
             */
            auto it = wallet_values.find("comment");
            
            if (it != wallet_values.end())
            {
                wtx.values()["comment"] = it->second;
            }
            
            /**
             * Check for the to.
             */
            it = wallet_values.find("to");
            
            if (it != wallet_values.end())
            {
                wtx.values()["to"] = it->second;
            }

            destination::tx_t dest_tx = addr.get();

            auto ret =
                globals::instance().wallet_main()->send_money_to_destination(
                dest_tx, amount, wtx
            );
            
            if (ret.first)
            {
                pairs["error.code"] = "0";
                pairs["error.message"] = "success";
            }
            else
            {
                log_error(
                    "Stack, send coins failed, error = " << ret.second << "."
                );

                pairs["error.code"] = "-1";
                pairs["error.message"] = ret.second;
            }
            
            /**
             * If we are an (SPV) client we need to reset and update
             * the transaction bloom filter.
             */
            if (globals::instance().is_client_spv() == true)
            {
                globals::instance().io_service().post(
                    globals::instance().strand().wrap([this]()
                {
                    /**
                     * Reset the (SPV) transaction bloom filter.
                     */
                    globals::instance().spv_reset_bloom_filter();
                    
                    if (m_tcp_connection_manager)
                    {
                        auto tcp_connections =
                            m_tcp_connection_manager->tcp_connections()
                        ;
                        
                        for (auto & i : tcp_connections)
                        {
                            if (auto connection = i.second.lock())
                            {
                                /**
                                 * Send the filterload message.
                                 */
                                connection->send_filterload_message(
                                    *globals::instance(
                                    ).spv_transaction_bloom_filter()
                                );
                            }
                        }
                    }
                }));
            }
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::queue_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, amount, destination, wallet_values]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "transaction";
        
        /**
         * Set the pairs value.
         */
        pairs["value"] = "queued";
        
        address addr(destination);
        
        auto perform_queue = true;
        
        if (addr.is_valid() == false)
        {
            log_error("Stack, queue coins failed, invalid destination address.");
            
            perform_queue = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "invalid destination address";
        }

        if (amount < constants::min_txout_amount)
        {
            log_error("Stack, queue coins failed, amount too small.");
            
            perform_queue = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "amount too small";
        }
        
        if (
            amount + globals::instance().transaction_fee() >
            globals::instance().wallet_main()->get_balance()
            )
        {
            log_error("Stack, queue coins failed, insufficient funds.");
            
            perform_queue = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "insufficient funds";
        }
        
        if (globals::instance().wallet_main()->is_locked())
        {
            log_error("Stack, queue coins failed, wallet is locked.");
            
            perform_queue = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "wallet is locked";
        }
        
        if (m_tcp_connection_manager->is_connected() == false)
        {
            log_error("Stack, queue coins failed, not connected to network.");
            
            perform_queue = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "not connected to network";
        }
        
        if (perform_queue)
        {
            /**
             * Allocate the transaction_wallet.
             */
            transaction_wallet wtx(globals::instance().wallet_main().get());
            
            /**
             * Check for a comment.
             */
            auto it = wallet_values.find("comment");
            
            if (it != wallet_values.end())
            {
                wtx.values()["comment"] = it->second;
            }
            
            /**
             * Check for the to.
             */
            it = wallet_values.find("to");
            
            if (it != wallet_values.end())
            {
                wtx.values()["to"] = it->second;
            }

            destination::tx_t dest_tx = addr.get();

            auto ret =
                globals::instance().wallet_main()->queue_money_for_destination(
                dest_tx, amount, wtx, pairs
            );
            
            if (ret.first)
            {
                pairs["error.code"] = "0";
                pairs["error.message"] = "success";
            }
            else
            {
                log_error(
                    "Stack, queue coins failed, error = " << ret.second << "."
                );

                pairs["error.code"] = "-1";
                pairs["error.message"] = ret.second;
            }
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::send_queued_coins()
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this]()
    {
        if (globals::instance().wallet_main()->send_queued_coins() == true)
        {
            /**
             * If we are an (SPV) client we need to reset and update
             * the transaction bloom filter.
             */
            if (globals::instance().is_client_spv() == true)
            {
                globals::instance().io_service().post(
                    globals::instance().strand().wrap([this]()
                {
                    /**
                     * Reset the (SPV) transaction bloom filter.
                     */
                    globals::instance().spv_reset_bloom_filter();
                    
                    if (m_tcp_connection_manager)
                    {
                        auto tcp_connections =
                            m_tcp_connection_manager->tcp_connections()
                        ;
                        
                        for (auto & i : tcp_connections)
                        {
                            if (auto connection = i.second.lock())
                            {
                                /**
                                 * Send the filterload message.
                                 */
                                connection->send_filterload_message(
                                    *globals::instance(
                                    ).spv_transaction_bloom_filter()
                                );
                            }
                        }
                    }
                }));
            }
        }
    }));
}

void stack_impl::cancel_queued_coins()
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this]()
    {
        globals::instance().wallet_main()->cancel_queued_coins();
    }));
}

void stack_impl::start_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (m_mining_manager)
    {
        auto it = mining_values.find("algorithm");
        
        if (it != mining_values.end())
        {
            if (it->second == "proof-of-work")
            {
                m_mining_manager->start_proof_of_work();
            }
        }
    }
}

void stack_impl::stop_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (m_mining_manager)
    {
        globals::instance().io_service().post(globals::instance().strand().wrap(
            [this, mining_values]()
        {
            auto it = mining_values.find("algorithm");
            
            if (it != mining_values.end())
            {
                if (it->second == "proof-of-work")
                {
                    m_mining_manager->stop_proof_of_work();
                }
            }
        }));
    }
}

bool stack_impl::wallet_exists(const bool & is_client)
{
    auto path = filesystem::data_path();
    
    if (is_client == true)
    {
        path += "client/";
    }
    
    std::ifstream ifs(path + "wallet.dat");

    return ifs.good();
}

void stack_impl::wallet_encrypt(const std::string & passphrase)
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this, passphrase]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "encrypt";
        
        if (globals::instance().wallet_main()->encrypt(passphrase))
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to encrypt wallet";
        }
    
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::wallet_lock()
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "lock";
        
        if (globals::instance().wallet_main()->lock())
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to lock wallet";
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::wallet_unlock(const std::string & passphrase)
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this, passphrase]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "unlock";
        
        if (globals::instance().wallet_main()->unlock(passphrase))
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to unlock wallet";
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::wallet_change_passphrase(
    const std::string & passphrase_old, const std::string & password_new
    )
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this, passphrase_old, password_new]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "change_passphrase";
        
        if (
            globals::instance().wallet_main()->change_passphrase(
            passphrase_old, password_new)
            )
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to change wallet passphrase";
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

bool stack_impl::wallet_is_crypted(const std::uint32_t & wallet_id)
{
    if (wallet_id == 0)
    {
        return globals::instance().wallet_main()->is_crypted();
    }
    
    return false;
}

bool stack_impl::wallet_is_locked(const std::uint32_t & wallet_id)
{
    if (wallet_id == 0)
    {
        return globals::instance().wallet_main()->is_locked();
    }
    
    return false;
}

std::string stack_impl::wallet_hd_keychain_seed()
{
    if (globals::instance().wallet_main()->is_locked() == false)
    {
        return globals::instance().wallet_main()->hd_keychain_seed();
    }
    
    return std::string();
}

void stack_impl::wallet_generate_address(const std::string & label)
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, label]()
    {
        if (label == "*")
        {
            log_error(
                "Stack failed to generate wallet address, invalid account "
                "name = " << label << "."
            );
            
            return;
        }
        
        /**
         * If the wallet is not locked, top up the key pool.
         */
        if (globals::instance().wallet_main()->is_locked() == false)
        {
            globals::instance().wallet_main()->top_up_key_pool();
        }
        
        /**
         * Allocate the public key.
         */
        key_public pub_key;
        
        if (
            globals::instance().wallet_main()->get_key_from_pool(
            pub_key, false) == false
            )
        {
            log_error(
                "Stack failed to generate wallet address, keypool ran out."
            );
        }
        else
        {
            const auto & key_id = pub_key.get_id();
            
            globals::instance().wallet_main()->set_address_book_name(
                key_id, label
            );
        }
    }));
}

void stack_impl::rpc_send(const std::string & command_line)
{
    auto tmp = command_line;
    
    /**
     * Trim whitespace.
     */
    boost::algorithm::trim(tmp);
    
    std::vector<std::string> parts;
    
    /**
     * Split the command line.
     */
    boost::split(parts, tmp, boost::is_any_of(" "));
    
    if (parts.size() > 0)
    {
        std::string command;
        
        std::vector<std::string> params;
        
        auto index = 0;
        
        for (auto & i : parts)
        {
            /**
             * Get the command and params.
             */
            if (index++ == 0)
            {
                command = i;
            }
            else
            {
                params.push_back(i);
            }
        }
        
        if (command.size() > 0)
        {
            /**
             * The url.
             */
            auto url = "http://localhost";

            /**
             * The headers.
             */
            std::map<std::string, std::string> headers;
            
            /**
             * The body.
             */
            std::string body;
            
            /**
             * A JSON-RPC request.
             */
            struct
            {
                std::string method;
                boost::property_tree::ptree params;
                std::string id;
            } request;
            
            /**
             * Set the method.
             */
            request.method = command;
            
            /**
             * Set the id.
             */
            request.id = std::to_string(std::rand());

            try
            {
                boost::property_tree::ptree pt;

                /**
                 * Put method into property tree.
                 */
                pt.put(
                    "method", request.method,
                    rpc_json_parser::translator<std::string> ()
                );
                
                boost::property_tree::ptree pt_params;
                
                /** 
                 * Put the params.
                 */
                if (params.size() > 0)
                {
                    for (auto & i : params)
                    {
                        boost::property_tree::ptree pt_param;
                        
                        pt_param.put(
                            "", i, rpc_json_parser::translator<std::string> ()
                        );
                        
                        pt_params.push_back(std::make_pair("", pt_param));
                    }
                
                    pt.put_child("params", pt_params);
                }
                else
                {
                    boost::property_tree::ptree pt_params;
                    
                    pt_params.push_back(
                        std::make_pair("", boost::property_tree::ptree())
                    );
                    
                    pt.put_child("params", pt_params);
                }
                
                /**
                 * Put id into property tree.
                 */
                pt.put(
                    "id", request.id,
                    rpc_json_parser::translator<std::string> ()
                );
                
                /**
                 * The std::stringstream.
                 */
                std::stringstream ss;
                
                /**
                 * Write property tree to json file.
                 */
                rpc_json_parser::write_json(ss, pt, true);
                
                /**
                 * Set the body.
                 */
                body = ss.str();
                
                /**
                 * Set the content-length.
                 */
                headers["content-length"] = body.size();
                
                /**
                 * POST the request.
                 */
                url_post(url, protocol::default_rpc_port, headers, body,
                    [this] (const std::map<std::string, std::string> & headers,
                    const std::string & body)
                {
                    if (body.size() > 0)
                    {
                        /**
                         * The JSON
                         */
                        std::stringstream json;

                        std::stringstream ss;

                        ss << body;

                        boost::property_tree::ptree pt;
                        
                        std::map<std::string, std::string> result;
                        
                        try
                        {
                            read_json(ss, pt);

                            /**
                             * Allocate the pairs.
                             */
                            std::map<std::string, std::string> pairs;
                            
                            /**
                             * Set the pairs type.
                             */
                            pairs["type"] = "rpc";
                            
                            try
                            {
                                auto & error = pt.get_child("error");
                                
                                (void)error;

                                /**
                                 * Set the pairs value.
                                 */
                                pairs["value"] =
                                    error.get_child("code"
                                    ).get<std::string> ("") + " : " +
                                    error.get_child("message"
                                    ).get<std::string> ("")
                                ;

                                /**
                                 * Set the pairs error.code.
                                 */
                                pairs["error.code"] = "-1";
                                
                                /**
                                 * Set the pairs error.message.
                                 */
                                pairs["error.message"] =
                                    error.get_child("message"
                                    ).get<std::string> ("")
                                ;
                                
                            }
                            catch (...)
                            {
                                auto & result = pt.get_child("result");
                             
                                try
                                {
                                    rpc_json_parser::write_json(json, result);
                                }
                                catch (...)
                                {
                                    json << result.get<std::string> ("");
                                }

                                /**
                                 * Set the pairs value.
                                 */
                                pairs["value"] =
                                    json.str() == "null" ? "" : json.str()
                                ;

                                /**
                                 * Set the pairs error.code.
                                 */
                                pairs["error.code"] = "0";
                                
                                /**
                                 * Set the pairs error.message.
                                 */
                                pairs["error.message"] = "success";
                            }
                            
                            /**
                             * Callback
                             */
                            if (m_status_manager)
                            {
                                m_status_manager->insert(pairs);
                            }
                        }
                        catch (std::exception & e)
                        {
                            log_error(
                                "Stack rpc send failed to parse JSON-RPC "
                                "response, what = " << e.what() << "."
                            );
                        }
                    }
                });
            }
            catch (std::exception & e)
            {
                log_error(
                    "Stack failed to create RPC request, what = " <<
                    e.what() << "."
                );
            }
        }
    }
}

void stack_impl::rescan_chain(const std::int64_t & time_from)
{
    if (globals::instance().is_client_spv() == true)
    {
        globals::instance().io_service().post(
            globals::instance().strand().wrap([this, time_from]()
        {
            const auto * block_last =
                globals::instance().spv_block_last().get()
            ;

            auto found_last_header = false;
            
            while (block_last && block_last->height() > 0)
            {
                /**
                 * Get the time of the last block header.
                 */
                auto time_last_header = static_cast<std::time_t> (
                    block_last->block_header().timestamp)
                ;
                
                /**
                 * Set the default rescan time to that of the wallet.
                 */
                auto time_rescan =
                    globals::instance().spv_time_wallet_created()
                ;
                
                /**
                 * If the time to scan from is before the wallet creation time
                 * use the wallet creation time.
                 */
                if (time_from > 0)
                {
                    time_rescan = std::max(
                        static_cast<std::time_t> (time_from),
                        globals::instance().spv_time_wallet_created()
                    );
                }
                
                if (time_last_header < time_rescan)
                {
                    std::unique_ptr<block_merkle> merkle_block(
                        new block_merkle(*block_last)
                    );
                    
                    globals::instance().set_spv_block_last(*merkle_block);
                    globals::instance().set_spv_best_block_height(
                        merkle_block->height()
                    );
                    
                    log_info(
                        "Stack is performing (SPV) rescan from time "
                        "height " << merkle_block->height() << "."
                    );
                    
                    found_last_header = true;
                    
                    break;
                }
                else
                {
                    block_last =
                        globals::instance().spv_block_merkles()[
                        block_last->block_header().hash_previous_block].get()
                    ;
                }
            }

            if (found_last_header == false)
            {
                auto spv_checkpoints =
                    checkpoints::instance().get_spv_checkpoints()
                ;
                
                auto it = spv_checkpoints.rbegin();
                
                for (; it != spv_checkpoints.rend(); ++it)
                {
                    if (
                        it->second.second <
                        globals::instance().spv_time_wallet_created()
                        )
                    {
                        std::unique_ptr<block_merkle> merkle_block(
                            new block_merkle(it->first, it->second.first)
                        );
                        
                        globals::instance().set_spv_block_last(merkle_block);
                        globals::instance().set_spv_best_block_height(
                            merkle_block->height()
                        );
                        
                        globals::instance().spv_block_merkles().clear();
                        
                        globals::instance().spv_block_merkles()[
                            merkle_block->get_hash()].reset(
                            new block_merkle(*merkle_block)
                        );
                        
                        log_info(
                            "Stack is performing (SPV) rescan from checkpoint"
                            " height " << merkle_block->height() << "."
                        );
                
                        break;
                    }
                }
            }
            
            /**
             * Set (SPV) use getblocks to false so that when we reconnect
             * we are requesting headers instead.
             */
            globals::instance().set_spv_use_getblocks(false);
            
            auto it = globals::instance().spv_block_merkles().begin();
            
            while (it != globals::instance().spv_block_merkles().end())
            {
                if (
                    it->second && it->second->height() >
                    globals::instance().spv_best_block_height()
                    )
                {
                    it = globals::instance().spv_block_merkles().erase(it);
                }
                else
                {
                    ++it;
                }
            }
        
            for (auto & i : m_tcp_connection_manager->tcp_connections())
            {
                if (auto connection = i.second.lock())
                {
                    connection->stop();
                }
            }
        }));
    }
    else
    {
        /**
         * Set the configuration to rescan on the next start.
         */
        m_configuration.set_wallet_rescan(true);
        
        /**
         * Save the configuration.
         */
        m_configuration.save();
    }
}

void stack_impl::ban_ip_address(
    const std::string & ip_or_endpoint, const std::uint32_t & duration
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, ip_or_endpoint, duration]()
    {
        /**
         * Split the address and port.
         */
        std::vector<std::string> parts;

		/**
         * First try IPv6.
         */
		boost::split(parts, ip_or_endpoint, boost::is_any_of("[,]"));
        
        if (parts.size() == 1)
        {
        	parts.clear();
            
            /**
             * If not IPv6 try IPv4.
             */
        	boost::split(parts, ip_or_endpoint, boost::is_any_of(":"));
        }
        else
        {
        	parts.erase(parts.begin());
        }
    
        if (parts.size() > 0)
        {
            auto addr = parts[0];
            
            /**
             * Ban the IP address for duration.
             */
            network::instance().ban_address(addr, duration);
            
            auto tcp_connections =
                m_tcp_connection_manager->tcp_connections()
            ;
            
            /**
             * Disconnect all nodes with a matching IP address.
             */
            if (tcp_connections.size() > 0)
            {
                for (auto & i : tcp_connections)
                {
                    if (auto j = i.second.lock())
                    {
                        if (auto k = j->get_tcp_transport().lock())
                        {
                            try
                            {
                                if (
                                    k->socket().remote_endpoint().address(
                                    ).to_string() == addr
                                    )
                                {
                                    j->stop();
                                }
                            }
                            catch (...)
                            {
                                // ...
                            }
                        }
                    }
                }
            }
        }
    }));
}

void stack_impl::set_configuration_wallet_transaction_history_maximum(
    const std::time_t & val
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, val]()
    {
        m_configuration.set_wallet_transaction_history_maximum(val);
        
        m_configuration.save();
    }));
}

const std::time_t
    stack_impl::configuration_wallet_transaction_history_maximum() const
{
    return m_configuration.wallet_transaction_history_maximum();
}

void stack_impl::set_configuration_wallet_transaction_fee(
    const std::int64_t & val
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, val]()
    {
        auto wallet_transaction_fee = val;
        
        /**
         * Check for too high transaction fee.
         */
        if (wallet_transaction_fee > (constants::default_tx_fee * 10))
        {
            wallet_transaction_fee = constants::default_tx_fee;
        }
        
        /**
         * Check for too low transaction fee.
         */
        if (wallet_transaction_fee < (constants::default_tx_fee / 10))
        {
            wallet_transaction_fee = constants::default_tx_fee;
        }
        
        log_info(
            "Stack is setting wallet transaction fee to " <<
            (static_cast<double> (wallet_transaction_fee) / constants::coin) <<
            "."
        );
        
        m_configuration.set_wallet_transaction_fee(wallet_transaction_fee);
        
        m_configuration.save();
        
        globals::instance().set_transaction_fee(wallet_transaction_fee);
        
        assert(
            m_configuration.wallet_transaction_fee() ==
            globals::instance().transaction_fee()
        );
    }));
}

const std::int64_t stack_impl::configuration_wallet_transaction_fee() const
{
    assert(
        m_configuration.wallet_transaction_fee() ==
        globals::instance().transaction_fee()
    );
    
    return m_configuration.wallet_transaction_fee();
}

void stack_impl::set_configuration_network_tcp_read_maximum(
    const std::size_t & val
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, val]()
    {
        /**
         * Enforce an 8 KB/s read minimum.
         */
        auto read = std::max(
            static_cast<std::size_t> (8192), val
        );
        
        m_configuration.set_network_tcp_read_maximum(read);
        
        /**
         * Set the read time per token.
         */
        tcp_transport::token_bucket_read().set_time_per_token(read);
        
        /**
         * Set the read burst per token (200%).
         */
        tcp_transport::token_bucket_read().set_time_per_burst(read * 2);
        
        m_configuration.save();
    }));
}

const std::size_t stack_impl::configuration_network_tcp_read_maximum() const
{
    return m_configuration.network_tcp_read_maximum();
}

void stack_impl::set_configuration_network_tcp_write_maximum(
    const std::size_t & val
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, val]()
    {
        /**
         * Enforce an 8 KB/s write minimum.
         */
        auto write = std::max(
            static_cast<std::size_t> (8192), val
        );
    
        m_configuration.set_network_tcp_write_maximum(write);
        
        /**
         * Set the write time per token.
         */
        tcp_transport::token_bucket_write().set_time_per_token(write);
        
        /**
         * Set the write burst per token (200%).
         */
        tcp_transport::token_bucket_write().set_time_per_burst(write * 2);
        
        m_configuration.save();
    }));
}

const std::size_t stack_impl::configuration_network_tcp_write_maximum() const
{
    return m_configuration.network_tcp_write_maximum();
}

void stack_impl::url_get(
    const std::string & url,
    const std::function<void (const std::map<std::string, std::string> &,
    const std::string &)> & f
    )
{
    std::shared_ptr<http_transport> t =
        std::make_shared<http_transport>(globals::instance().io_service(), url)
    ;

    t->start(
        [this, f](
        boost::system::error_code ec, std::shared_ptr<http_transport> t)
    {
        if (ec)
        {
            f(std::map<std::string, std::string> (), std::string());
		}
		else
		{
            f(t->headers(), t->response_body());
		}
	});
}

void stack_impl::url_post(
    const std::string & url, const std::uint16_t & port,
    const std::map<std::string, std::string> & headers,
    const std::string & body,
    const std::function<void (const std::map<std::string, std::string> &,
    const std::string &)> & f
    )
{
    std::shared_ptr<http_transport> t =
        std::make_shared<http_transport>(globals::instance().io_service(), url)
    ;

    t->headers() = headers;
    
    t->set_request_body(body);
    
    t->start(
        [this, f](
        boost::system::error_code ec, std::shared_ptr<http_transport> t)
    {
        if (ec)
        {
            f(std::map<std::string, std::string> (), std::string());
		}
		else
		{
            f(t->headers(), t->response_body());
		}
	}, port);
}

bool stack_impl::process_block(
    const std::shared_ptr<tcp_connection> & connection,
    const std::shared_ptr<block> & blk
    )
{
    if (globals::instance().state() < globals::state_stopping)
    {
        /**
         * Lock the main std::recursive_mutex.
         */
        std::lock_guard<std::recursive_mutex> l1(g_mutex);
        
#define TIME_PROCCESS_BLOCK_SPEED 0

#if (defined TIME_PROCCESS_BLOCK_SPEED && TIME_PROCCESS_BLOCK_SPEED)
        auto start = std::chrono::system_clock::now();
#endif // TIME_PROCCESS_BLOCK_SPEED

        /**
         * Check for duplicate.
         */
        auto hash_block = blk->get_hash();
        
        if (globals::instance().block_indexes().count(hash_block) > 0)
        {
            log_debug(
                "Stack failed to process block, already have " <<
                globals::instance().block_indexes()[hash_block]->height()
                << " " << hash_block.to_string().substr(0, 20) << "."
            );
            
            return false;
        }
        
        if (globals::instance().orphan_blocks().count(hash_block) > 0)
        {
            log_debug(
                "Stack failed to process block, already have (orphan) " <<
                hash_block.to_string().substr(0, 20) << "."
            );
            
            return false;
        }

        try
        {
            /**
             * Preliminary checks.
             */
            if (blk->check_block(connection) == false)
            {
                log_error("Stack failed to process block, check block failed.");

                return false;
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "Stack failed to process block, check block failed, "
                "what = " << e.what() << "."
            );
            
            return false;
        }

        /**
         * If don't already have its previous block, shunt it off to holding
         * area until we get it.
         */
        if (
            globals::instance().block_indexes().count(
            blk->header().hash_previous_block) == 0
            )
        {
            log_none(
                "Stack failed to process block, orphan block, previous = " <<
                blk->header().hash_previous_block.to_string().substr(0, 20) <<
                "."
            );
            
            std::shared_ptr<block> blk2(new block(*blk));
            
            globals::instance().orphan_blocks().insert(
                std::make_pair(hash_block, blk2)
            );
            
            globals::instance().orphan_blocks_by_previous().insert(
                std::make_pair(blk2->header().hash_previous_block, blk2)
            );
            
			/**
             * When using headers first chain synchronization we do not
             * need to handle orphan blocks.
             */
			if (
   	         	globals::instance().peer_use_headers_first_chain_sync(
                ) == true
            	)
            {
            	log_none(
             	   "Stack got orphan block in header first chain "
                    "synchronization mode."
                );
                
                return false;
            }
            else
   			{
                /**
                 * Ask this guy to fill in what we're missing.
                 */
                if (connection)
                {
                    connection->send_getblocks_message(
                        stack_impl::get_block_index_best(),
                        utility::get_orphan_root(blk2)
                    );
                    
                    /**
                     * Getblocks may not obtain the ancestor block rejected
                     * earlier.
                     */
                    if (utility::is_initial_block_download() == false)
                    {
                        std::vector<inventory_vector> getdata;
                        
                        getdata.push_back(
                            inventory_vector(inventory_vector::type_msg_block,
                            utility::wanted_by_orphan(blk2))
                        );
                        
                        connection->send_getdata_message(getdata);
                    }
                }
            }
            
            return true;
        }

        /**
         * Store to disk.
         */
        if (blk->accept_block(m_tcp_connection_manager) == false)
        {
            log_error("Stack failed to process block, accept block failed.");
         
            return false;
        }

        /**
         * Recursively process any orphan blocks that depended on this one.
         */
        std::vector<sha256> work_queue;
        
        work_queue.push_back(hash_block);
        
        for (auto i = 0; i < work_queue.size(); i++)
        {
            auto hash_previous = work_queue[i];
            
            for (
                auto it = globals::instance().orphan_blocks_by_previous(
                ).lower_bound(hash_previous); it != globals::instance(
                ).orphan_blocks_by_previous().upper_bound(hash_previous); ++it
                )
            {
                std::shared_ptr<block> & block_orphan = it->second;

                log_debug(
                    "Stack is processing orphan block " <<
                    block_orphan->get_hash().to_string().substr(0, 29) << "."
                );
                
                if (block_orphan->accept_block(m_tcp_connection_manager))
                {
                    work_queue.push_back(block_orphan->get_hash());
                }

                globals::instance().orphan_blocks().erase(
                    block_orphan->get_hash()
                );
            }
            
            globals::instance().orphan_blocks_by_previous().erase(
                hash_previous
            );
        }
#if (defined TIME_PROCCESS_BLOCK_SPEED && TIME_PROCCESS_BLOCK_SPEED)
        std::chrono::duration<double> elapsed_seconds =
            std::chrono::system_clock::now() - start
        ;
        
        log_info(
            "Stack process block took " << elapsed_seconds.count() <<
            " seconds."
        );
#endif // TIME_PROCCESS_BLOCK_SPEED
        
        log_debug("Stack processed block, accepted.");

		/**
		 * If we are operating in (peer) headers first chain synchronization
         * mode callback to download more blocks (if we are not fully
         * synchronized).
         */
		if (
			globals::instance().peer_use_headers_first_chain_sync() == true
            )
  		{
            /**
             * Starts the (peer) block headers first synchronization timer.
             */
            timer_peer_headers_first_.expires_from_now(
                std::chrono::milliseconds(25)
            );
            timer_peer_headers_first_.async_wait(
                strand_network_.wrap(
                    [this](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            on_peer_headers_first();
                        }
                    }
                )
            );
    	}

        return true;
    }
    
    return false;
}

void stack_impl::spv_block_merkles_save()
{
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this]()
    {
        const auto & block_merkles = globals::instance().spv_block_merkles();
        
        log_info(
            "Stack is saving " << block_merkles.size() <<
            " block_merkle's to disk."
        );
    
        auto f = std::make_shared<file> ();
        
        auto count = 0;
        
        std::string path =
            filesystem::data_path() + "block-headers-client-thin.dat"
        ;
        std::string path_last =
            filesystem::data_path() + "block-headers-client-thin.dat.last"
        ;
        
        /**
         * Make a copy of the previous file so we can load it should this one
         * become corrupted.
         */
        std::rename(path.c_str(), path_last.c_str());
        
        if (f && f->open(path.c_str(), "wb"))
        {
            /**
             * Allocate the buffer.
             */
            data_buffer buffer_blocks;
            
            for (auto & i : block_merkles)
            {
                if (i.second)
                {
                    if ((count % 500) == 0)
                    {
                        log_debug(
                            "Stack is saving block_merkle " <<
                            i.second->height() << ":" <<
                            i.first.to_string().substr(0, 8) << "."
                        );
                    }
                    
                    /**
                     * Encode the block_merkle into the buffer.
                     */
                    i.second->encode(buffer_blocks, true);
                    
                    count++;
                }
            }
            
            /**
             * Calculate the checksum of all encoded block_merkles.
             */
            auto checksum = buffer_blocks.checksum();
            
            /**
             * Write the checksum to the end of the file.
             */
            buffer_blocks.write_uint32(checksum);
            
            /**
             * Write the block buffer.
             */
            f->write(buffer_blocks.data(), buffer_blocks.size());

            /**
             * Flush
             */
            f->fflush();
            
            /**
             * Sync
             */
            f->fsync();
        }
        
        log_info("Stack (SPV) saved " << count << " block_merkle's to disk.");
        
        /**
         * Starts the block_merkle's save timer.
         */
        timer_block_merkles_save_.expires_from_now(
            std::chrono::seconds(60 * 60)
        );
        timer_block_merkles_save_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        /**
                         * Save the (SPV) block_merkle's to disk.
                         */
                        spv_block_merkles_save();
                    }
                }
            )
        );
    }));
}

void stack_impl::spv_block_merkles_load(std::uint8_t & trys)
{
    assert(trys <= 1);

    std::string path =
        filesystem::data_path() + "block-headers-client-thin.dat"
    ;
    std::string path_last =
        filesystem::data_path() + "block-headers-client-thin.dat.last"
    ;
    
    auto f = std::make_shared<file> ();
    
    if (f && f->open(trys == 0 ? path.c_str() : path_last.c_str(), "rb"))
    {
        data_buffer buffer_blocks(f);
  
        auto size = f->size();
        
        std::uint32_t checksum = 0;
        
        if (size > 0)
        {
            auto bytes = buffer_blocks.read_bytes(size);
            
            std::memcpy(
                &checksum, &bytes[size - sizeof(checksum)], sizeof(checksum)
            );

            buffer_blocks = data_buffer(
                reinterpret_cast<const char *> (&bytes[0]),
                bytes.size() - sizeof(checksum)
            );
        }

        /**
         * Calculate the checksum of all encoded block_merkles and compare
         * with the checksum from the end of the file.
         */
        if (checksum != buffer_blocks.checksum())
        {
            log_error("Stack got invalid checksum for " << path << ".");
            
            /**
             * Try loading the .last file and call load again if no last file
             * is found do nothing.
             */
            if (trys < 1)
            {
                trys++;
                
                spv_block_merkles_load(trys);
            }
            else
            {
                trys++;
                
                /**
                 * Invalid files will be rewritten during chain synchronisation.
                 */
            }
        }
        else
        {
            /**
             * The number of blocks we've loaded from disk.
             */
            auto blocks_loaded = 0;
            
            std::uint32_t block_number = 0;

            while (buffer_blocks.remaining() >= block::header_length)
            {
                block_merkle merkle_block;
                
                if (merkle_block.decode(buffer_blocks, true) == true)
                {
                    /**
                     * Check blocks for BIP9 deployment proposals.
                     */
                    if (
                        version_bits::instance().block_version_has_bit_set(
                        merkle_block.block_header().version,
                        version_bits::deployment_bit_segwit) == true
                        )
                    {
                        log_debug(
                            "Stack loaded block " << merkle_block.height() <<
                            ", detected deployment proposal (segwit)."
                        );
                    }
                    else
                    {
                        log_debug(
                            "Stack loaded block " << merkle_block.height() <<
                            "."
                        );
                    }
                    
                    if (merkle_block.height() > block_number)
                    {
                        block_number = merkle_block.height();

                        globals::instance().set_spv_block_last(merkle_block);
                        globals::instance().set_spv_best_block_height(
                            block_number
                        );
                    }
                    
                    globals::instance().spv_block_merkles()[
                        merkle_block.get_hash()
                    ].reset(new block_merkle(merkle_block));
                    
                    /**
                     * Increment the number of blocks loaded.
                     */
                    blocks_loaded++;
                    
                    /**
                     * Four weeks worth of blocks (T = 10 mins).
                     */
                    enum { four_weeks_of_blocks = 4032 };
                    
                    /**
                     * @note Consider writing the number of block_merkles
                     * so that regardless of block timing, etc we can calculate
                     * the percentage loaded from disk correctly.
                     */
                    blocks_loaded =
                        std::min(static_cast<std::uint32_t> (blocks_loaded),
                        static_cast<std::uint32_t> (four_weeks_of_blocks))
                    ;
         
                    /**
                     * Calculate the percentage of blocks loaded based on a
                     * maximum (blocks_to_retain).
                     */
                    float percentage =
                        ((float)blocks_loaded /
                        (float)four_weeks_of_blocks) * 100.0f
                    ;
                    
                    /**
                     * Only callback status every 100 blocks.
                     */
                    if ((blocks_loaded % 100) == 0)
                    {
                        /**
                         * Allocate the status.
                         */
                        std::map<std::string, std::string> status;

                        /**
                         * Set the status type.
                         */
                        status["type"] = "database";

                        /**
                         * Format the block verification progress percentage.
                         */
                        std::stringstream ss;

                        ss <<
                            std::fixed << std::setprecision(2) << percentage
                        ;
            
                        /**
                         * Set the status value.
                         */
                        status["value"] = "Verifying " + ss.str() + "%";

                        /**
                         * The block verify percentage.
                         */
                        status["blockchain.verify.percent"] =
                            std::to_string(percentage)
                        ;
            
                        /**
                         * Callback
                         */
                        if (m_status_manager)
                        {
                            m_status_manager->insert(status);
                        }
                    }
                }
                else
                {
                    break;
                }
            }
            
            if (blocks_loaded <= 1)
            {
                log_warn(
                    "Stack didn't seem to load enough blocks(" <<
                    blocks_loaded << "), restarting from genesis."
                );
            
                globals::instance().set_spv_block_last(nullptr);
                globals::instance().set_spv_best_block_height(0);
                globals::instance().spv_block_merkles().clear();
            }
            
            log_debug(
                "Stack loaded blocks, best height = " <<
                globals::instance().spv_best_block_height() << "."
            );
            
            float percentage = 100.0f;
        
            /**
             * Allocate the status.
             */
            std::map<std::string, std::string> status;

            /**
             * Set the status type.
             */
            status["type"] = "database";

            /**
             * Format the block verification progress percentage.
             */
            std::stringstream ss;

            ss <<
                std::fixed << std::setprecision(2) << percentage
            ;

            /**
             * Set the status value.
             */
            status["value"] = "Verifying " + ss.str() + "%";

            /**
             * The block verify percentage.
             */
            status["blockchain.verify.percent"] =
                std::to_string(percentage)
            ;

            /**
             * Callback
             */
            if (m_status_manager)
            {
                m_status_manager->insert(status);
            }
        }
    }
    else
    {
        /**
         * Try loading the .last file.
         */
        if (trys < 1)
        {
            trys++;
            
            spv_block_merkles_load(trys);
        }
        else
        {
            trys++;
            
            /**
             * Invalid files will be rewritten during chain synchronisation.
             */
        }
    }
}

configuration & stack_impl::get_configuration()
{
    return m_configuration;
}

std::shared_ptr<address_manager> & stack_impl::get_address_manager()
{
    return m_address_manager;
}

std::shared_ptr<mining_manager> & stack_impl::get_mining_manager()
{
    return m_mining_manager;
}

std::shared_ptr<status_manager> & stack_impl::get_status_manager()
{
    return m_status_manager;
}

const std::shared_ptr<status_manager> & stack_impl::get_status_manager() const
{
    return m_status_manager;
}


std::shared_ptr<tcp_acceptor> & stack_impl::get_tcp_acceptor()
{
    return m_tcp_acceptor;
}

std::shared_ptr<tcp_connection_manager> &
    stack_impl::get_tcp_connection_manager()
{
    return m_tcp_connection_manager;
}

std::recursive_mutex & stack_impl::mutex()
{
    return g_mutex;
}

std::shared_ptr<db_env> & stack_impl::get_db_env()
{
    return g_db_env;
}

void stack_impl::set_block_index_genesis(block_index * val)
{
    g_block_index_genesis = val;
}

block_index * stack_impl::get_block_index_genesis()
{
    return g_block_index_genesis;
}

void stack_impl::set_block_index_best(block_index * val)
{
    g_block_index_best = val;
}

block_index * stack_impl::get_block_index_best()
{
    return g_block_index_best;
}

big_number & stack_impl::get_best_chain_trust()
{
    return g_best_chain_trust;
}

big_number & stack_impl::get_best_invalid_trust()
{
    return g_best_invalid_trust;
}

block_index * stack_impl::insert_block_index(
    const sha256 & hash_block
    )
{
    block_index * ret = 0;
    
    if (hash_block == 0)
    {
        return ret;
    }
    
    auto it = globals::instance().block_indexes().find(hash_block);
    
    if (it != globals::instance().block_indexes().end())
    {
        ret = it->second;
    }
    else
    {
        ret = new block_index();
    
        if (ret == 0)
        {
            throw std::runtime_error(
                "Failed to insert block index (unable to allocate memory)."
            );
        }
        
        ret->set_hash_block(hash_block);
        
        globals::instance().block_indexes()[hash_block] = ret;
    }

    return ret;
}

const std::int32_t & stack_impl::local_block_count() const
{
    if (globals::instance().is_client_spv() == true)
    {
        return globals::instance().spv_best_block_height();
    }
    
    return globals::instance().best_block_height();
}

const std::uint32_t stack_impl::peer_block_count() const
{
    return
        std::max(globals::instance().peer_block_counts().median(),
        checkpoints::instance().get_total_blocks_estimate())
    ;
}

double stack_impl::difficulty(block_index * index) const
{
    if (globals::instance().is_client_spv() == true)
    {
        if (globals::instance().spv_block_last())
        {
            static std::uint32_t g_last_bits = 0;
            
            if (g_last_bits == 0)
            {
                std::int32_t block_height = 0;
                
                for (auto & i : globals::instance().spv_block_merkles())
                {
                    if (
                        i.second &&
                        i.second->height() > block_height
                        )
                    {
                        block_height = i.second->height();
                        
                        g_last_bits = i.second->block_header().bits;
                    }
                }
            }
            
            if (
                g_last_bits != globals::instance().spv_block_last(
                )->block_header().bits
                )
            {
                g_last_bits =
                    globals::instance().spv_block_last(
                    )->block_header().bits
                ;
            }
        
            return utility::difficulty_from_bits(g_last_bits);
        }
    }
    else
    {
        block_index * index_tmp = 0;
        
        if (index)
        {
            index_tmp = index;
        }
        else
        {
            index_tmp = const_cast<block_index *> (utility::get_last_block_index(
                stack_impl::get_block_index_best())
            );
        }

        if (index_tmp)
        {
            return utility::difficulty_from_bits(index_tmp->bits());
        }
    }
    
    return 1.0;
}

std::uint64_t stack_impl::network_hash_per_second()
{
    if (g_block_index_best)
    {
        enum { target_spacing_work_minimum = 30 };
        
        std::int64_t target_spacing_work = target_spacing_work_minimum;
        
        auto interval = 72;
        
        auto index = get_block_index_genesis();
        
        auto index_previous = get_block_index_genesis();
        
        while (index)
        {
            if (index->is_proof_of_work())
            {
                std::int64_t actual_spacing_work =
                    index->time() - index_previous->time()
                ;
                
                target_spacing_work =
                    ((interval - 1) * target_spacing_work +
                    actual_spacing_work + actual_spacing_work) / (interval + 1)
                ;
                
                target_spacing_work = std::max(
                    target_spacing_work,
                    static_cast<std::int64_t> (target_spacing_work_minimum)
                );
                
                index_previous = index;
            }
            
            index = index->block_index_next();
        }
        
        double ghps = difficulty() * 4.294967296 / target_spacing_work;
        
        return ghps * 1000000000.0f;
    }

    return 0;
}

void stack_impl::on_error(const std::map<std::string, std::string> & pairs)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);
    
    stack_.on_error(pairs);
}

void stack_impl::on_status(const std::map<std::string, std::string> & pairs)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);
    
    stack_.on_status(pairs);
}

void stack_impl::on_status(
    const std::vector< std::map<std::string, std::string> > & pairs
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);
    
    stack_.on_status(pairs);
}

void stack_impl::on_reject_message(message & msg)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);
    
    if (msg.protocol_reject().message == "tx")
    {
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "protocol.reject";
        
        /**
         * Set the type.
         */
        status["protocol.reject.message"] = msg.protocol_reject().message;

        /**
         * Set the wallet.balance.
         */
        status["protocol.reject.ccode"] = std::to_string(
            msg.protocol_reject().ccode
        );
        
        /**
         * Set the wallet.balance.
         */
        status["protocol.reject.reason"] = msg.protocol_reject().reason;
        
        if (msg.protocol_reject().data.size() == sha256::digest_length)
        {
            auto hash_tx = sha256::from_digest(&msg.protocol_reject().data[0]);
            
            /**
             * Set the protocol.reject.data.
             */
            status["protocol.reject.data"] = hash_tx.to_string();
        }
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
}

void stack_impl::on_spv_merkle_block(
    const std::shared_ptr<tcp_connection> & connection,
    block_merkle & merkle_block,
    const std::vector<transaction> & transactions_received
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);
    
    /**
     * Drop block headers newer than our wallet creation time.
     */
    if (
        merkle_block.get_merkle_tree_partial().total_transactions() == 0 &&
        merkle_block.block_header().timestamp >=
        globals::instance().spv_time_wallet_created()
        )
    {
        return;
    }

    /**
     * Get the matched transaction hashes.
     */
    const auto & transactions_matched = merkle_block.transactions_matched();
    
    /**
     * Add all of the matched transactions.
     */
    std::vector<sha256> hashes_tx;
    
    for (auto & i : transactions_matched)
    {
        hashes_tx.push_back(i.second);
    }
    
    /**
     * If set to true the blockchain has been synchronised.
     */
    auto chain_in_sync = false;
    
    if (hashes_tx.size() > 0)
    {
        /**
         * The number of false positives.
         */
        auto false_positive = 0;
        
        /**
         * Track bloom filter false positive rate.
         */
        for (auto & i : hashes_tx)
        {
            if (
                globals::instance().wallet_main()->transactions().count(i
                ) == 0
                )
            {
                false_positive++;
            }
        }
        
        /**
         * Calculate the false positive rate.
         */
        globals::instance().set_spv_average_false_positive_rate(
            globals::instance().spv_average_false_positive_rate() *
            (1.0 - 0.01 * merkle_block.get_merkle_tree_partial(
            ).total_transactions() / 1400) + 0.01 * false_positive / 1400
        );

        /**
         * Rate limit logging calls during sync.
         */
        if (
            (globals::instance().spv_block_last()->height() %
            (utility::is_spv_initial_block_download() == true ? 10 : 1)) == 0
            )
        {
            log_info(
                "Stack (SPV) false positive rate = " << std::setprecision(5) <<
                (globals::instance().spv_average_false_positive_rate() <
                0.0001 ? 0.0001 :
                globals::instance().spv_average_false_positive_rate()) <<
                ", false_positive = " << false_positive << ", (cutoff = " <<
                globals::instance().spv_false_positive_rate() * 10.0f << ")."
            );
        }

        /**
         * If the false positive rate is greater than the globally configured
         * rate drop the connection.
         */
        if (
            globals::instance().spv_average_false_positive_rate() >
            globals::instance().spv_false_positive_rate() * 100.0f
            )
        {
            log_error(
                "Stack (SPV) false positive rate (" << std::setprecision(5) <<
                globals::instance().spv_average_false_positive_rate() <<
                ") too high, disconnecting peer."
            );
            
            /**
             * Reset the (SPV) transaction bloom filter.
             */
            globals::instance().spv_reset_bloom_filter();
            
            if (connection)
            {
                connection->stop();
                
                return;
            }
        }
        else if (false)
        {
            /**
             * @note We can reset the transaction_bloom_filter here if the
             * false positive rate seems degraded.
             */
        }
        
        /**
         * @note Test key sync key generation on more platforms.
         */
#if 1
        /**
         * Always maintain more keys than transactions (mainly for wallet
         * restore).
         */
        std::size_t number_of_wallet_keys = 0;
        
        if (globals::instance().wallet_main()->is_crypted() == true)
        {
            number_of_wallet_keys =
                globals::instance().wallet_main()->crypted_keys().size()
            ;
        }
        else
        {
            number_of_wallet_keys =
                globals::instance().wallet_main()->keys().size()
            ;
        }
        
        log_info(
            "Stack, (SPV) wallet keys = " << number_of_wallet_keys <<
            ", transactions = " <<
            globals::instance().wallet_main()->transactions().size() << "."
        );

        /**
         * Spawn a detached thread to perform the key generation.
         */
        std::thread([this, number_of_wallet_keys]()
        {
            enum { lookahead = 6 };
        
            if (
                (globals::instance().wallet_main()->transactions().size() +
                m_configuration.wallet_keypool_size() / 2)
                >= number_of_wallet_keys
                )
            {
                log_info(
                    "Stack, (SPV) is generating " << lookahead << " keys."
                );
            
                for (auto i = 0; i < lookahead; i++)
                {
                    /**
                     * If the wallet is not locked, top up the key pool.
                     */
                    if (globals::instance().wallet_main()->is_locked() == false)
                    {
                        globals::instance().wallet_main()->top_up_key_pool();
                    }
                    
                    /**
                     * Allocate the public key.
                     */
                    key_public pub_key;
                    
                    if (
                        globals::instance().wallet_main()->get_key_from_pool(
                        pub_key, false) == false
                        )
                    {
                        log_error(
                            "Stack, (SPV) failed to generate wallet address, "
                            "keypool ran out."
                        );
                    }
                }
            }
            
        }).detach();
#endif
    }
    
    /**
     * Get the block hash.
     */
    const auto & hash_block = merkle_block.get_hash();
    
    /**
     * Get the previous block hash.
     */
    const auto & hash_block_previous =
        merkle_block.block_header().hash_previous_block
    ;
    
    /**
     * Check for the previous block.
     */
    if (
        globals::instance().spv_block_merkles().count(hash_block_previous) == 0
        )
    {
        /**
         * Rate limit logging calls.
         */
        if ((globals::instance().spv_block_last()->height() % 10) == 0)
        {
            /**
             * We've got an orphan block.
             */
            log_info(
                "Stack got orphan block " << hash_block.to_string() <<
                ", previous = " << hash_block_previous.to_string() <<
                ", last block  = " <<
                globals::instance().spv_block_last()->get_hash().to_string() <<
                ", height = " <<
                globals::instance().spv_block_last()->height() << "."
            );
        }
        
        /**
         * Get the start height of the peer.
         */
        auto start_height =
            (connection == nullptr ? 0 :
            connection->protocol_version_start_height())
        ;

        /**
         * Do not proccess orphan blocks older than two weeks.
         */
        if (
            merkle_block.block_header().timestamp <
            std::time(0) - 14 * 24 * 60 * 60
            )
        {
            /**
             * Rate limit logging calls.
             */
            if ((globals::instance().spv_block_last()->height() % 10) == 0)
            {
                log_warn(
                    "Stack is dropping SPV orphan " <<
                    merkle_block.get_hash().to_string() <<
                    " older than two weeks (" <<
                    std::time(0) -
                    merkle_block.block_header().timestamp << ")."
                );
            }
            
            if (connection)
            {
                connection->set_spv_dos_score(
                    connection->spv_dos_score() + 0.025
                );
            }
            
            return;
        }

        const auto & orphan_block_last =
            globals::instance().spv_block_orphan_last()
        ;

        if (
            globals::instance().spv_block_last()->height() > start_height &&
            (orphan_block_last && orphan_block_last->get_hash() !=
            hash_block_previous)
            )
        {
            log_info("Stack is sending getblocks due to orphan.");

            if (
                connection && connection->identifier() ==
                globals::instance().spv_active_tcp_connection_identifier()
                )
            {
                /**
                 * Get the block_locator hashes.
                 */
                const auto & block_locator_hashes =
                    globals::instance().spv_block_locator_hashes()
                ;
                
                /**
                 * Allocate the block_locator with the last and
                 * first hash.
                 */
                block_locator locator(block_locator_hashes);
                
                /**
                 * Send the getblocks message.
                 */
                connection->send_getblocks_message(sha256(), locator);
            }
        }

        globals::instance().spv_block_merkle_orphans()[
            hash_block_previous].reset(new block_merkle(merkle_block))
        ;
        globals::instance().spv_block_merkle_orphan_transactions()[
            hash_block_previous] = transactions_received
        ;
        
        globals::instance().set_spv_block_orphan_last(merkle_block);
        
        return;
    }
    
    const auto & merkle_block_previous =
        globals::instance().spv_block_merkles()[hash_block_previous]
    ;

    assert(merkle_block_previous);
    
    /**
     * Set the height.
     */
    merkle_block.set_height(merkle_block_previous->height() + 1);
    
    /**
     * Four weeks worth of blocks (T = 10 mins).
     */
    enum { four_weeks_of_blocks = 4032 };
    
    /**
     * Save blocks to disk every 28 days worth.
     */
    if (merkle_block.height() % four_weeks_of_blocks == 0)
    {
        log_info(
            "Stack is saving chain state and freeing memory because we have "
            "four weeks worth of blocks."
        );
        
        const auto * ptr_merkle_block = &merkle_block;
        
        for (
            auto i = 0; ptr_merkle_block && i < four_weeks_of_blocks; i++
            )
        {
            ptr_merkle_block =
                globals::instance().spv_block_merkles()[
                ptr_merkle_block->block_header().hash_previous_block
            ].get();
        }
        
        auto hash_previous_block =
            ptr_merkle_block ?
            ptr_merkle_block->block_header().hash_previous_block : sha256()
        ;
        
        /**
         * Get rid of in-memory blocks that are older than
         * four_weeks_of_blocks.
         */
        while (ptr_merkle_block)
        {
            ptr_merkle_block =
                globals::instance().spv_block_merkles()[
                hash_previous_block].get()
            ;
            
            if (
                ptr_merkle_block &&
                (ptr_merkle_block->height() % four_weeks_of_blocks) != 0)
            {
                hash_previous_block =
                    ptr_merkle_block->block_header().hash_previous_block
                ;
        
                globals::instance().spv_block_merkles().erase(
                    ptr_merkle_block->get_hash()
                );
            }
            else
            {
                break;
            }
        }
        
        /**
         * Save the merkle blocks to disk.
         */
        spv_block_merkles_save();
    }
    
    /**
     * Guess the time of the transaction(s).
     */
    std::time_t time_tx =
        merkle_block.block_header().timestamp / 2 +
        merkle_block_previous->block_header().timestamp / 2
    ;
    
    /**
     * Verify the block difficulty
     */
    if (
        block::check_proof_of_work(merkle_block.get_hash(),
        merkle_block.block_header().bits) == false
        )
    {
        log_error(
            "Stack got block with invalid difficulty target = " <<
            merkle_block.block_header().bits << ", hash = " <<
            merkle_block.get_hash().to_string() << "."
        );
    
        /**
         * Increment the DoS score for the connection (SPV one hour).
         */
        if (connection)
        {
            connection->set_spv_dos_score(connection->spv_dos_score() + 25.0);
        }
        
        return;
    }
    
    /**
     * Verify hard checkpoints.
     */
    if (
        checkpoints::instance().check_hardened(merkle_block.height(),
        hash_block) == false
        )
    {
        /**
         * Get the checkpoints.
         */
        auto checkpoints =
            (constants::test_net ?
            checkpoints::instance().get_checkpoints_test_net() :
            checkpoints::instance().get_checkpoints())
        ;
        
        /**
         * Get the expected hash or null if there is no checkpoint.
         */
        auto hash_expected = checkpoints[merkle_block.height()];
    
        log_error(
            "Stack got block with checkpoint mismatch, height = " <<
            merkle_block.height() << ", hash = " << hash_block.to_string() <<
            ", expected = " << hash_expected.to_string() << "."
        );
        
        /**
         * Increment the DoS score for the connection (SPV one hour).
         */
        if (connection)
        {
            connection->set_spv_dos_score(connection->spv_dos_score() + 1.0);
        }
        
        return;
    }
    
    /**
     * First check that the block appends to the main chain.
     */
    if (
        globals::instance().spv_block_last() &&
        hash_block_previous ==
        globals::instance().spv_block_last()->get_hash()
        )
    {
        /**
         * Rate limit logging calls.
         */
        if ((merkle_block.height() % 100) == 0)
        {
            log_info(
                "Stack is adding (SPV) block " <<
                merkle_block.height() << " to the main chain."
            );
        }
        
        /**
         * Add the merkle block to the (SPV) merkle blocks map.
         */
        globals::instance().spv_block_merkles()[hash_block].reset(
            new block_merkle(merkle_block)
        );
        
        /**
         * Set the last merkle block.
         */
        globals::instance().set_spv_block_last(merkle_block);
        
        /**
         * Rate limit logging calls during initial download.
         */
        if (utility::is_spv_initial_block_download() == true)
        {
            if ((merkle_block.height() % 100) == 0)
            {
                log_info(
                    "Stack set current (SPV) block height to " <<
                    merkle_block.height() << "."
                );
            }
        }
        else
        {
            log_info(
                "Stack set current (SPV) block height to " <<
                merkle_block.height() << "."
            );
        }
        
        /**
         * Set the current block height, time and transaction hashes.
         */
        set_spv_block_height(merkle_block.height(), time_tx, hashes_tx);
        
        /**
         * Check if this block height is the same as the median of all
         * connected peers.
         */
        if (
            merkle_block.height() == peer_block_count() ||
            (connection && merkle_block.height() >=
            connection->protocol_version_start_height())
            )
        {
            chain_in_sync = true;
        }
    }
    else if (globals::instance().spv_block_merkles().count(hash_block) > 0)
    {
        /**
         * Rate limit logging calls.
         */
        if ((globals::instance().spv_block_last()->height() % 10) == 0)
        {
            log_info(
                "Stack got duplicate (SPV) merkle block from " <<
                (connection ? connection->identifier() : 0) << "."
            );
        }

        /**
         * Add the merkle block to the (SPV) merkle blocks map.
         */
        globals::instance().spv_block_merkles()[hash_block].reset(
            new block_merkle(merkle_block)
        );
        
        const auto * block_last = globals::instance().spv_block_last().get();
        
        while (block_last && block_last->height() > merkle_block.height())
        {
            block_last = globals::instance().spv_block_merkles()[
                block_last->block_header().hash_previous_block
            ].get();
        }
        
        if (block_last && block_last->get_hash() == merkle_block.get_hash())
        {
            /**
             * Set the current block height, time and transaction hashes.
             */
            set_spv_block_height(merkle_block.height(), time_tx, hashes_tx);
        
            if (
                merkle_block.height() ==
                globals::instance().spv_block_last()->height())
            {
                globals::instance().set_spv_block_last(merkle_block);
            }
        }
    }
    else
    {
        /**
         * We've are on a fork.
         */
        
        /**
         * Ignore forks before the last checkpoint.
         */
        if (
            merkle_block.height() <=
            checkpoints::instance().get_total_blocks_estimate()
            )
        {
            return;
        }

        log_info(
            "Stack detected fork to chain at height " <<
            merkle_block.height() << "."
        );
        
        globals::instance().spv_block_merkles()[hash_block].reset(
            new block_merkle(merkle_block)
        );
        
        /**
         * The fork is shorter than the main chain.
         */
        if (
            merkle_block.height() <=
            globals::instance().spv_block_last()->height()
            )
        {
            return;
        }

        const auto * b1 = &merkle_block, * b2 =
            globals::instance().spv_block_last().get()
        ;

        while (b1 && b2 && b1->get_hash() != b2->get_hash())
        {
            /**
             * Traverse backwards until we find where the fork meets the main
             * chain.
             */
            b1 =
                globals::instance().spv_block_merkles()[
                b1->block_header().hash_previous_block].get()
            ;
            
            if (b1->height() < b2->height())
            {
                b2 =
                    globals::instance().spv_block_merkles()[
                    b2->block_header().hash_previous_block].get()
                ;
            }
        }
        
        log_info(
            "Stack is reorganising chain from height " << b1->height() <<
            ", to height " << merkle_block.height() << "."
        );

        std::vector<sha256> hashes_tx;

        /**
         * Set the current block height (to unconfirmed depth), time and
         * transaction hashes.
         */
        set_spv_block_height(
            std::numeric_limits<std::int32_t>::max(), time_tx, hashes_tx
        );

        b1 = &merkle_block;

        while (b1->height() > b2->height())
        {
            /**
             * Get the matched transaction hashes.
             */
            const auto & transactions_matched = b1->transactions_matched();
            
            std::vector<sha256> hashes_tx;
            
            for (auto & i : transactions_matched)
            {
                hashes_tx.push_back(i.second);
            }
    
            /**
             * Set the current block height, time and transaction hashes.
             */
            set_spv_block_height(merkle_block.height(), time_tx, hashes_tx);

            b1 =
                globals::instance().spv_block_merkles()[
                b1->block_header().hash_previous_block].get()
            ;
            
            time_tx =
                b1->block_header().timestamp / 2 +
                globals::instance().spv_block_merkles()[b1->block_header(
                ).hash_previous_block]->block_header().timestamp / 2
            ;
        }
        
        /**
         * Set the last block.
         */
        globals::instance().set_spv_block_last(merkle_block);

        /**
         * Check if this block height is the same as the median of all
         * connected peers.
         */
        if (
            merkle_block.height() == peer_block_count() ||
            (connection && merkle_block.height() >=
            connection->protocol_version_start_height())
            )
        {
            chain_in_sync = true;
        }
    }

    /**
     * Check if the blockchain is synchronised.
     */
    if (chain_in_sync == true)
    {
        log_info(
            "Stack has completed chain synchronisation at block " <<
            merkle_block.height() << "."
        );
    }

    /**
     * @note Because spv_best_block_height was updated in spv_block_last
     * we need use the next block height in this check indicating readyness
     * for the next block height(current + 1).
     */
    if (
        merkle_block.height() + 1 > globals::instance().spv_best_block_height()
        )
    {
        /**
         * Set the best (SPV) block height.
         */
        globals::instance().set_spv_best_block_height(merkle_block.height());
        
        /**
         * Set the current block height, time and transaction hashes.
         */
        set_spv_block_height(merkle_block.height(), time_tx, hashes_tx);
    }

    /**
     * Verify that the next block was not a previously received orphan.
     */
    if (
        hash_block == globals::instance().spv_block_last()->get_hash() &&
        globals::instance().spv_block_merkle_orphans().count(hash_block) > 0
        )
    {
        log_info(
            "*** handle orphan " << hash_block.to_string().substr(0, 16)
        );
        
        auto merkle_block_orphan = std::make_shared<block_merkle> (
            *globals::instance().spv_block_merkle_orphans()[hash_block]
        );

        auto merkle_block_orphan_transactions =
            globals::instance().spv_block_merkle_orphan_transactions()[
            hash_block]
        ;

        globals::instance().spv_block_merkle_orphans().erase(hash_block);
        globals::instance().spv_block_merkle_orphan_transactions().erase(
            hash_block
        );
        
        /**
         * This is a recursive call.
         */
        if (connection)
        {
            globals::instance().io_service().post(
                globals::instance().strand().wrap([this, connection,
                merkle_block_orphan, merkle_block_orphan_transactions]()
            {
                on_spv_merkle_block(
                    connection, *merkle_block_orphan,
                    merkle_block_orphan_transactions
                );
            }));
        }
    }
}

void stack_impl::set_spv_block_height(
    const std::int32_t & height, const std::time_t & time,
    const std::vector<sha256> & hashes_tx
    )
{
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    globals::instance().io_service().post(
        globals::instance().strand().wrap(
        [this, height, hashes_tx]()
    {
        /**
         * Inform the wallet manager that transactions may have been updated.
         */
        for (auto & i : hashes_tx)
        {
            /**
             * Inform the wallet manager.
             */
            wallet_manager::instance().on_spv_transaction_updated(height, i);
        }
    }));
}

bool stack_impl::on_peer_block_header(
    const std::shared_ptr<tcp_connection> & connection, block & blk
	)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_callback_);

    /**
     * If set to true the blockchain has been synchronised.
     */
    auto chain_in_sync = false;
    
    /**
     * Get the block hash.
     */
    const auto & hash_block = blk.get_hash();
    
    /**
     * Get the previous block hash.
     */
    const auto & hash_block_previous =
        blk.header().hash_previous_block
    ;
    
    /**
     * Check for the previous block.
     */
    if (
        globals::instance().peer_headers_first_blocks(
        ).count(hash_block_previous) == 0
        )
    {
        /**
         * Rate limit logging calls.
         */
        if (
        	globals::instance().peer_headers_first_block_last() &&
            (globals::instance().peer_headers_first_block_last(
            )->peer_headers_first_sync_height() % 10) == 0
            )
        {
            /**
             * We've got an orphan block.
             */
            log_info(
                "Stack got orphan block header " << hash_block.to_string() <<
                ", previous = " << hash_block_previous.to_string() <<
                ", last block  = " <<
                globals::instance().peer_headers_first_block_last(
                )->get_hash().to_string() << ", height = " <<
                globals::instance().peer_headers_first_block_last(
                )->peer_headers_first_sync_height() << "."
            );
        }

		return false;
    }
    
    const auto & block_previous =
        globals::instance().peer_headers_first_blocks()[hash_block_previous]
    ;

    assert(block_previous);

	/**
	 * Get the height.
     */
	auto height = block_previous->peer_headers_first_sync_height() + 1;

    /**
     * Set the height.
     */
    blk.set_peer_headers_first_sync_height(height);

    /**
     * First check that the block appends to the main chain.
     */
    if (
        globals::instance().peer_headers_first_block_last() &&
        hash_block_previous ==
        globals::instance().peer_headers_first_block_last()->get_hash()
        )
    {
        /**
         * Rate limit logging calls.
         */
        if ((blk.peer_headers_first_sync_height() % 100) == 0)
        {
            log_info(
                "Stack is adding (peer) block header " <<
                blk.get_hash().to_string().substr(0, 12) << ":" <<
                blk.peer_headers_first_sync_height() << " to the main chain."
            );
        }

        /**
         * Add the block header to the (peer) block header map.
         */
        globals::instance().peer_headers_first_blocks()[hash_block].reset(
            new block(blk)
        );
        
        /**
         * Map the block header height to the hash.
         */
        globals::instance().peer_headers_first_heights_and_hashes()[height] =
        	hash_block
        ;
        
        /**
         * Set the last block header.
         */
        globals::instance().set_peer_headers_first_block_last(blk);
        
        /**
         * Check if this block height is the same as the median of all
         * connected peers.
         */
        if (
            blk.peer_headers_first_sync_height() == peer_block_count() ||
            (connection && blk.peer_headers_first_sync_height() >=
            connection->protocol_version_start_height())
            )
        {
            chain_in_sync = true;
        }
    }
    else if (
    	globals::instance().peer_headers_first_blocks().count(hash_block) > 0
        )
    {
        /**
         * Rate limit logging calls.
         */
        if ((blk.peer_headers_first_sync_height() % 25) == 0)
        {
            log_info(
                "Stack got duplicate (peer) block header " <<
                hash_block.to_string() << " from " <<
                (connection ? connection->identifier() : 0) << "."
            );
        }

        /**
         * Add the block header to the (peer) block header map.
         */
        globals::instance().peer_headers_first_blocks()[hash_block].reset(
            new block(blk)
        );
        
        const auto * block_last =
        	globals::instance().peer_headers_first_block_last().get()
        ;

        while (
        	block_last && block_last->peer_headers_first_sync_height() >
            blk.peer_headers_first_sync_height()
            )
        {
        	if (
           		globals::instance().peer_headers_first_blocks().count(
                block_last->header().hash_previous_block) > 0
                )
         	{
                block_last = globals::instance().peer_headers_first_blocks()[
                    block_last->header().hash_previous_block
                ].get();
            }
            else
            {
            	block_last = nullptr;
            }
        }
        
        if (block_last && block_last->get_hash() == blk.get_hash())
        {
            if (
                blk.peer_headers_first_sync_height() ==
                globals::instance().peer_headers_first_block_last(
                )->peer_headers_first_sync_height())
            {
                globals::instance().set_peer_headers_first_block_last(blk);
            }
        }
        
        /**
         * @note Consider this return value.
         */
        return false;
    }
    else
    {
        /**
         * We've are on a fork.
         */

        /**
         * Ignore forks before the last checkpoint.
         */
        if (
            blk.peer_headers_first_sync_height() <=
            checkpoints::instance().get_total_blocks_estimate()
            )
        {
            return false;
        }

        log_info(
            "Stack detected fork to chain at height " <<
         	blk.peer_headers_first_sync_height() << "."
        );
        
        globals::instance().peer_headers_first_blocks()[hash_block].reset(
            new block(blk)
        );
        
        /**
         * The fork is shorter than the main chain.
         * @note This is possibly redundant and useless.
         */
//        if (
//            blk.peer_headers_first_sync_height() <=
//            globals::instance().peer_headers_first_block_last(
//            )->peer_headers_first_sync_height()
//            )
//        {
//            return false;
//        }

        const auto * b1 = &blk, * b2 =
            globals::instance().peer_headers_first_block_last().get()
        ;
        
        while (b1 && b2 && b1->get_hash() != b2->get_hash())
        {
        	if (
				globals::instance().peer_headers_first_blocks().count(
                b1->header().hash_previous_block) > 0
                )
         	{
                /**
                 * Traverse backwards until we find where the fork meets the
                 * main chain.
                 */
                b1 =
                    globals::instance().peer_headers_first_blocks()[
                    b1->header().hash_previous_block].get()
                ;
                
                if (
                    b1->peer_headers_first_sync_height() <
                    b2->peer_headers_first_sync_height()
                    )
                {
                	if (
						globals::instance().peer_headers_first_blocks().count(
                        b2->header().hash_previous_block) > 0
                        )
                 	{
                    	b2 =
							globals::instance().peer_headers_first_blocks()[
							b2->header().hash_previous_block].get()
                    	;
                    }
                    else
                    {
                    	b2 = nullptr;
                    }
                }
            }
            else
            {
            	break;
            }
        }
        
        log_info(
            "Stack is reorganising chain from height " <<
        	b1->peer_headers_first_sync_height() << ", to height " <<
         	blk.peer_headers_first_sync_height() << "."
        );

        b1 = &blk;

        while (
        	b1->peer_headers_first_sync_height() >
            b2->peer_headers_first_sync_height()
        	)
        {
            b1 =
                globals::instance().peer_headers_first_blocks()[
                b1->header().hash_previous_block].get()
            ;
        }
        
        /**
         * Set the last block.
         */
        globals::instance().set_peer_headers_first_block_last(blk);

        /**
         * Reorganize the coins_cache back to the best valid block_index
         * of this fork that we have in common.
         */
        const auto & block_indexes = globals::instance().block_indexes();
       
        /**
         * @note we need to erase all of the block indexes back to the fork.
         */
#if 0
        auto it = block_indexes.find(blk.get_hash());
        
        if (it != block_indexes.end())
        {
        	while (
            	it != block_indexes.end() && it->second != nullptr &&
                it->second->block_index_next() != nullptr
                )
         	{
          		auto it2 = block_indexes.find(
                	it->second->block_index_next()->get_block_hash()
            	);
                
				if (it2 != block_indexes.end())
				{
     				it = block_indexes.find(
                    	it->second->block_index_next(
                        )->block_index_next()->get_block_hash()
                	);
                 
                 	globals::instance().block_indexes().erase(it2);
                }
          	}
        }
#endif

		auto it = block_indexes.find(blk.get_hash());
        
        if (it != block_indexes.end())
        {
        	coins_cache::instance().set_block_index_best(it->second);
        }
        else
        {
			// ...
        }

        /**
         * Check if this block height is the same as the median of all
         * connected peers.
         */
        if (
            blk.peer_headers_first_sync_height() == peer_block_count() ||
            (connection && blk.peer_headers_first_sync_height() >=
            connection->protocol_version_start_height())
            )
        {
            chain_in_sync = true;
        }
    }

    /**
     * Check if the blockchain is synchronised.
     */
    if (chain_in_sync == true)
    {
        log_info(
            "Stack has completed header synchronisation at block " <<
            blk.peer_headers_first_sync_height() << "."
        );
    }
    
    time_last_peer_block_header_ = std::time(0);
    
    return true;
}

void stack_impl::on_status_block()
{
    /**
     * Allocate the status.
     */
    std::map<std::string, std::string> status;
    
    /**
     * Set the status type.
     */
    status["type"] = "block";
    
    /**
     * Set the status value.
     */
    status["value"] = "Downloading blocks";
    
    /**
     * The local block count.
     */
    status["block.count.local"] = std::to_string(local_block_count());
    
    /**
     * The peer block count.
     */
    status["block.count.peer"] = std::to_string(peer_block_count());

    /**
     * Calculate the percentage of the number of downloaded blocks.
     */
    double percentage =
        (static_cast<double> (local_block_count()) /
        static_cast<double> (peer_block_count()) * 100.0f)
    ;
    
    /**
     * The block download percent.
     */
    status["block.download.percent"] = std::to_string(percentage);

    /**
     * The block difficulty.
     */
    status["block.difficulty"] = std::to_string(difficulty());
    
    /**
     * Callback
     */
    m_status_manager->insert(status);
    
    /**
     * Starts the block status timer.
     */
    timer_status_block_.expires_from_now(std::chrono::seconds(1));
    timer_status_block_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_block();
                }
            }
        )
    );
}

void stack_impl::on_status_wallet()
{
    /**
     * Get the balance.
     */
    auto balance = globals::instance().wallet_main()->get_balance();
    
    /**
     * Get the unconfirmed balance.
     */
    auto unconfirmed_balance =
        globals::instance().wallet_main()->get_unconfirmed_balance()
    ;
    
    /**
     * Get the immature.
     */
    auto immature_balance =
        globals::instance().wallet_main()->get_immature_balance()
    ;
    
    /**
     * Keep that last known balance.
     */
    static std::int64_t g_balance = 0;
    
    /**
     * If the balance has changed callback status.
     */
    if (balance != g_balance)
    {
        g_balance = balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.
         */
        status["wallet.balance.unconfirmed"] =
            std::to_string(unconfirmed_balance)
        ;
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Keep that last known unconfirmed balance.
     */
    static std::int64_t g_unconfirmed_balance = 0;
    
    /**
     * If the unconfirmed balance has changed callback status.
     */
    if (unconfirmed_balance != g_unconfirmed_balance)
    {
        g_unconfirmed_balance = unconfirmed_balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.
         */
        status["wallet.balance.unconfirmed"] =
            std::to_string(unconfirmed_balance)
        ;
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Keep that last known immature balance.
     */
    static std::int64_t g_immature_balance = 0;
    
    /**
     * If the immature balance has changed callback status.
     */
    if (immature_balance != g_immature_balance)
    {
        g_immature_balance = immature_balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.immature
         */
        status["wallet.balance.immature"] =
            std::to_string(immature_balance)
        ;
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    if (globals::instance().is_client_spv() == true)
    {
        /**
         * Check if the wallet key pool has been topped up.
         */
        if (
            std::time(0) -
            globals::instance().wallet_main()->time_key_pool_did_top_up()
            <= 8
            )
        {
            log_info(
                "Stack, detected wallet key pool size change, resetting "
                "(SPV) transaction bloom filter."
            );
            
            /**
             * Reset the (SPV) transaction bloom filter.
             */
            globals::instance().spv_reset_bloom_filter();
            
            if (m_tcp_connection_manager)
            {
                auto tcp_connections =
                    m_tcp_connection_manager->tcp_connections()
                ;
                
                for (auto & i : tcp_connections)
                {
                    if (auto connection = i.second.lock())
                    {
                        /**
                         * Send the filterload message.
                         */
                        connection->send_filterload_message(
                            *globals::instance(
                            ).spv_transaction_bloom_filter()
                        );
                    }
                }
            }
        }
    
        /**
         * Keep the last known (SPV) block height.
         */
        static std::uint32_t g_spv_best_block_height = 0;
        
        /**
         * If the block has changed callback status.
         */
        if (
            g_spv_best_block_height !=
            globals::instance().spv_best_block_height()
            )
        {
            g_spv_best_block_height =
                globals::instance().spv_best_block_height()
            ;
            
            /**
             * Get the transactions.
             */
            auto transactions =
                globals::instance().wallet_main()->transactions()
            ;
            
            /**
             * Callback each transaction that has less than (confirmations + 1)
             * confirmations.
             */
            for (auto & i : transactions)
            {
                if (
                    i.second.is_confirmed() &&
                    i.second.get_depth_in_main_chain() <=
                    (transaction::confirmations + 1)
                    )
                {
                    globals::instance().wallet_main()->on_transaction_updated(
                        i.first
                    );
                }
            }
            
            /**
             * If we are not synchronizing with the network callback BIP9
             * status.
             */
            if (utility::is_spv_initial_block_download() == false)
            {
                /**
                 * The block interval is 144 blocks per day.
                 */
                enum { block_interval = 144 };
                
                /**
                 * Get the last blocks_per_day block versions (BIP9).
                 */
                std::vector<std::uint32_t> versions;
                
                auto index = 0;
                
                const auto * block_last =
                    globals::instance().spv_block_last().get()
                ;

                while (block_last && block_last->height() > 0)
                {
                    versions.push_back(block_last->block_header().version);
                    
                    if (++index == block_interval)
                    {
                        break;
                    }

                    block_last =
                        globals::instance().spv_block_merkles()[
                        block_last->block_header().hash_previous_block].get()
                    ;
                }
                
                /**
                 * Get the BIP9 deployment proposals for the versions.
                 */
                auto deployment_proposals =
                    version_bits::instance(
                    ).deployment_proposals_from_versions(versions)
                ;
                
                /**
                 * Allocate the status pairs.
                 */
                std::vector< std::map<std::string, std::string> > pairs;
                
                /**
                 * Compile the deployment proposals into status objects.
                 */
                for (auto & i : deployment_proposals)
                {
                    /**
                     * Allocate the status.
                     */
                    std::map<std::string, std::string> status;
            
                    /**
                     * Set the status type.
                     */
                    status["type"] = "bip9";
                    
                    /**
                     * Set the status value.
                     */
                    status["value"] = "proposal";
                    
                    /**
                     * Set the bip9.block.interval.
                     */
                    status["bip9.block.interval"] =
                        std::to_string(block_interval)
                    ;
                    
                    /** 
                     * Copy the pairs.
                     */
                    for (auto & j : i)
                    {
                        status[j.first] = j.second;
                    }
                    
                    pairs.push_back(status);
                }
                
                /**
                 * Callback
                 */
                m_status_manager->insert(pairs);
            }
        }
    }
    else
    {
        /**
         * Keep the last known block height.
         */
        static std::uint32_t g_best_block_height = 0;
        
        /**
         * If the block has changed callback status.
         */
        if (g_best_block_height != globals::instance().best_block_height())
        {
            g_best_block_height = globals::instance().best_block_height();
            
            /**
             * Get the transactions.
             */
            auto transactions =
                globals::instance().wallet_main()->transactions()
            ;
            
            /**
             * Callback each transaction that has less than (confirmations + 1)
             * confirmations.
             */
            for (auto & i : transactions)
            {
                if (
                    i.second.is_confirmed() &&
                    i.second.get_depth_in_main_chain() <=
                    (transaction::confirmations + 1)
                    )
                {
                    globals::instance().wallet_main()->on_transaction_updated(
                        i.first
                    );
                }
            }
        }
    }
    
    /**
     * Starts the block status timer.
     */
    timer_status_wallet_.expires_from_now(std::chrono::seconds(8));
    timer_status_wallet_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_wallet();
                }
            }
        )
    );
}

void stack_impl::on_status_blockchain()
{
    if (globals::instance().is_client_spv() == true)
    {
        log_debug(
            "block_merkles: " << globals::instance().spv_block_merkles().size()
        );
        log_debug("relay_invs: " << globals::instance().relay_invs().size());
        log_debug(
            "relay_inv_expirations: " <<
            globals::instance().relay_inv_expirations().size()
        );
    }
    else
    {
        log_debug(
            "block_indexes: " << globals::instance().block_indexes().size()
        );
        log_debug(
            "orphan_blocks: " << globals::instance().orphan_blocks().size()
        );
        log_debug(
            "orphan_blocks_by_previous: " <<
            globals::instance().orphan_blocks_by_previous().size()
        );
        log_debug(
            "orphan_transactions: " <<
            globals::instance().orphan_transactions().size()
        );
        log_debug(
            "orphan_transactions_by_previous: " <<
            globals::instance().orphan_transactions_by_previous().size()
        );
        log_debug("relay_invs: " << globals::instance().relay_invs().size());
        log_debug(
            "relay_inv_expirations: " <<
            globals::instance().relay_inv_expirations().size()
        );
        
        if (globals::instance().money_supply() > 0)
        {
            /**
             * Allocate the status.
             */
            std::map<std::string, std::string> status;
            
            /**
             * Set the type.
             */
            status["type"] = "database";
            
            /**
             * Set the blockchain.money.
             */
            status["blockchain.money_supply"] =
                std::to_string(static_cast<double> (
                globals::instance().money_supply()) / constants::coin)
            ;
            
            /**
             * Callback
             */
            m_status_manager->insert(status);
        }
    }
    
    /**
     * Starts the blockchain status timer.
     */
    timer_status_blockchain_.expires_from_now(std::chrono::seconds(60));
    timer_status_blockchain_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_blockchain();
                }
            }
        )
    );
}

void stack_impl::on_database_env()
{
    if (globals::instance().is_client_spv() == false)
    {
        /**
         * Make sure no other threads can access the db_env for this scope.
         */
        std::lock_guard<std::recursive_mutex> l1(db_env::mutex_DbEnv());
        
        auto start = std::chrono::system_clock::now();
        
        if (stack_impl::get_db_env())
        {
            /**
             * Perform any statistics, logging, etc here.
             */
        }
        
        std::chrono::duration<double> elapsed_seconds =
            std::chrono::system_clock::now() - start
        ;
        
        log_info(
            "Database environment took " << elapsed_seconds.count() <<
            " seconds."
        );
        
        /**
         * Starts the database environment timer.
         */
        timer_database_env_.expires_from_now(std::chrono::seconds(60 * 60));
        timer_database_env_.async_wait(
            globals::instance().strand().wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_database_env();
                    }
                }
            )
        );
    }
}

void stack_impl::on_peer_headers_first()
{
    if (globals::instance().peer_use_headers_first_chain_sync() == true)
    {
        if (
        	globals::instance().peer_headers_first_blocks().size() >=
            peer_block_count()
        	)
        {
        	auto index = coins_cache::instance().block_index_best();
            
        	if (index != nullptr)
         	{
				auto height = index->height() + 1;

#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
        		if (globals::instance().block_indexes().size() >= 2016 * 8)
                {
            		log_info("Not fetching block (bcst) " << height << ".");
            
					return;
				}
#endif // BCASH_STRESS_TEST

                static std::map<std::uint32_t, std::time_t>
                	g_requested_heights_and_times
                ;
                
                if (g_requested_heights_and_times.count(height) > 0)
                {
                	if (
                 	   std::time(0) - g_requested_heights_and_times[height] > 8
                    	)
                 	{
                  		g_requested_heights_and_times.erase(height);
                        
                        /**
                         * Starts the (peer) block headers first
                         * synchronization timer.
                         */
                        timer_peer_headers_first_.expires_from_now(
                            utility::is_initial_block_download() ?
                            std::chrono::seconds(8) : std::chrono::seconds(8)
                        );

                        timer_peer_headers_first_.async_wait(
                            strand_network_.wrap(
                                [this](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        on_peer_headers_first();
                                    }
                                }
                            )
                        );
                  	}
                   	else
                    {
						/**
                         * Starts the (peer) block headers first
                         * synchronization timer.
                         */
                        timer_peer_headers_first_.expires_from_now(
                            utility::is_initial_block_download() ?
                            std::chrono::seconds(8) : std::chrono::seconds(8)
                        );

                        timer_peer_headers_first_.async_wait(
                            strand_network_.wrap(
                                [this](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        on_peer_headers_first();
                                    }
                                }
                            )
                        );
                        
                		return;
                    }
                }
                
                sha256 hash_next_block;
                
                if (
                	globals::instance().peer_headers_first_heights_and_hashes(
                    ).count(height) > 0
                    )
                {
                    hash_next_block = globals::instance(
                        ).peer_headers_first_heights_and_hashes()[height]
                    ;
               	}

         		if (
					globals::instance().peer_headers_first_blocks().count(
					hash_next_block) > 0
					)
                {

					g_requested_heights_and_times[height] = std::time(0);
                
                	const auto & block_next =
						globals::instance().peer_headers_first_blocks(
                        )[hash_next_block]
                    ;
  
                    log_debug(
                        "Next header to process = " <<
                        hash_next_block.to_string() << ", height = " <<
                        height << "."
                    );
                    
                    assert(block_next->get_hash() == hash_next_block);

                    std::map<std::uint32_t, std::shared_ptr<tcp_connection> >
                    	scores_and_tcp_connections
                    ;
                    
                    /**
                     * Create a random 2-digit score.
                     */
                    auto score_to_beat =
                        (random::uint32() ^ random::uint32()) % 100
                    ;
                    
                    if (m_tcp_connection_manager)
                    {
                        auto tcp_connections =
                            m_tcp_connection_manager->tcp_connections()
                        ;
                        
                        for (auto & i : tcp_connections)
                        {
                            if (auto j = i.second.lock())
                            {
                            	if (
                             	   j->peer_headers_first_block_is_stalled(
                                    ) == true
                                    )
                             	{
                              		log_debug(
										"Skipping connection " <<
                                        j->identifier() <<
                                        " because a block has stalled."
                                  	);
                                    
                              		j->stop();
                                
                                	continue;
                              	}
                                
                            	if (
                             	   j->peer_headers_first_blocks_requested() > 0
                                    )
                             	{
                              		log_info(
										"Skipping connection " <<
                                        j->identifier() << " because a block "
                                        "has been requested already."
                                  	);
                                    
                              		continue;
                              	}
 
                                /**
                                 * Calculate a 2-digit score for the
                                 * tcp_connection.
                                 */
                            	auto score_tcp_connection =
                               		(j->identifier() ^ random::uint32()) % 100
                                ;
                                
                                scores_and_tcp_connections[
                                	score_tcp_connection] = j
                                ;
                             
                             	log_debug(
									"tcp connection " << j->identifier() <<
                                    ", score_tcp_connection = " <<
                                    score_tcp_connection <<
                                    ", score_to_beat = " << score_to_beat
								);
                            }
                        }
                    }

                    auto score_top = 0;
                    
                    for (auto & i : scores_and_tcp_connections)
                    {
                        if (i.first > score_top)
						{
							score_top = i.first;
						}
                    }
                    
                    log_debug(
                        "score_top = " << score_top << ", score_to_beat = " <<
                        score_to_beat
                    );
                    
                    if (score_top > 0)
                    {
                    	assert(scores_and_tcp_connections.count(score_top) > 0);
                    }

                    std::shared_ptr<tcp_connection> connection;
                    
                    if (score_top > score_to_beat)
                    {
                        connection = scores_and_tcp_connections[score_top];
                    }
                    else
                 	{
                        auto it = scores_and_tcp_connections.begin();
                        
                        for (; it != scores_and_tcp_connections.end(); ++it)
                        {
                            if (
                            	it->second &&
                                it->second->is_transport_valid() == true
                                )
                            {
                                connection = it->second;
                                
                                break;
                            }
                        }
                  	}
                    
                    log_info(
                    	"TCP Connection " << (connection ?
                        connection->identifier() : 0) <<
                        " will fetch the next block."
                    );

                    auto should_fetch_block = false;

                    static block_index * g_index_last_best = 0;

                    if (
                    	connection != nullptr &&
                    	(index != g_index_last_best || local_block_count() <
                        globals::instance().peer_headers_first_blocks().size())
                        )
                    {
                        g_index_last_best = index;
                        
                        should_fetch_block = true;
                    }
                	
                    if (should_fetch_block == true)
                    {
                        std::vector<inventory_vector> getdata;

                        getdata.push_back(
                            inventory_vector(inventory_vector::type_msg_block,
                            hash_next_block)
                        );

                        if (connection)
                        {
                            connection->set_peer_headers_first_blocks_requested(
                                static_cast<std::uint32_t> (getdata.size())
                            );
                            
                            connection->send_getdata_message(getdata);
                        }

						auto index = 1;
                        
                        for (auto & i : scores_and_tcp_connections)
                        {
							if (
                                globals::instance(
                                ).peer_headers_first_heights_and_hashes().count(
                                height + index) > 0
                                )
                         	{
                          		std::vector<inventory_vector> getdata_extra;
                                
                                if (
                                	globals::instance().orphan_blocks().count(
                                    globals::instance(
                                    ).peer_headers_first_heights_and_hashes(
                                    )[height + index]) > 0
                                    )
                             	{
									continue;
                                }
                                
								getdata_extra.push_back(
                                    inventory_vector(
                                    inventory_vector::type_msg_block,
									globals::instance(
                                    ).peer_headers_first_heights_and_hashes(
                                    )[height + index])
								);

								/**
         						 * @note The loops method needs to be
                                 * deprecated for an alternative.
                                 */
                                auto loops = 128;
                                
                                if (height >= 200000)
                                {
                                	loops = loops / loops;
                                }
                                else if (height >= 100000)
                                {
                                	loops = loops / 2;
                                }
                				
        						for (auto j = 0; j < loops; j++)
              					{
                                    index++;
                                    
                                    if (
                                        globals::instance(
                                        ).peer_headers_first_heights_and_hashes(
                                        ).count(height + index) == 0
                                        )
                                     {
                                        continue;
                                     }
                                    
                                    if (
                                        globals::instance().orphan_blocks().count(
                                        globals::instance(
                                        ).peer_headers_first_heights_and_hashes(
                                        )[height + index]) > 0
                                        )
                                    {
                                        continue;
                                    }
                                    
                                    getdata_extra.push_back(
                                        inventory_vector(
                                        inventory_vector::type_msg_block,
                                        globals::instance(
                                        ).peer_headers_first_heights_and_hashes(
                                        )[height + index])
                                    );
                                }

                            	if (i.second && getdata_extra.size() > 0)
                            	{
                                	if (
                                 	   i.second->peer_headers_first_block_is_stalled(
                                        ) == true
                                    	)
                                 	{
                                      	log_info(
                                          "Skipping connection " <<
                                          i.second->identifier() << " because "
                                          "a block has stalled."
                                        );
                                    
                                      	i.second->stop();

                                    	continue;
                                  	}
                                  
                                    if (
                                    	i.second->peer_headers_first_blocks_requested(
                                        ) > 0
                                        )
                                    {
                                        log_debug(
                                        	"Skipping connection " <<
                                            i.second->identifier() <<
                                            " because a block has been "
                                            "requested already."
                                        );
     
                                        continue;
                                    }
                                  
                                    i.second->set_peer_headers_first_blocks_requested(
                                        static_cast<std::uint32_t> (
                                        getdata_extra.size())
                                    );
                                    
                                    i.second->send_getdata_message(
                                        getdata_extra
                                    );
                                    
                                    index++;
                            	}
							}
                        }
                    }
             	}
              	else
                {
                    log_error("Unable to find next header to process.");
               	}
         	}
        }
        else
        {
        	/**
         	 * We are waiting for more block headers.
             */
         	log_info(
				"Stack, waiting for more headers before starting block "
                "fetching."
            );
            
            /**
             * If we have tried to find blocks to download and have not
             * validated a header in some time disconnect ONE peer in attempt
             * to get getheaders flowing again.
             */
            if (
            	globals::instance().peer_headers_first_blocks().size() > 0 &&
                std::time(0) - time_last_peer_block_header_ >= 24
                )
            {
                auto tcp_connections =
                    m_tcp_connection_manager->tcp_connections()
                ;

                for (auto & i : tcp_connections)
                {
              		if (auto c = i.second.lock())
                	{
                 		log_info(
							"Stack, detected headers stalled, disconnecting "
                            "peer " << c->identifier() << "."
						);
                        
                 		c->stop();
                   
                   		break;
                 	}
                }
            }
        }
        
        /**
         * Starts the (peer) block headers first synchronization timer.
         */
        timer_peer_headers_first_.expires_from_now(
            utility::is_initial_block_download() ?
            std::chrono::seconds(8) : std::chrono::seconds(8)
        );
        timer_peer_headers_first_.async_wait(
            strand_network_.wrap(
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        on_peer_headers_first();
                    }
                }
            )
        );
    }
}

const boost::asio::ip::tcp::endpoint & stack_impl::local_endpoint() const
{
    return m_local_endpoint;
}

void stack_impl::create_directories()
{
    /**
     * Get the data path.
     */
    auto path_data = filesystem::data_path();
    
    log_info(
        "Stack creating path = " << path_data << "."
    );

    auto result = filesystem::create_path(path_data);
    
    if (result == 0 || result == filesystem::error_already_exists)
    {
        /**
         * Migration of data path from Y to Z can be performed here.
         */
#if 0
        /**
         * Get the old data path.
         */
        auto path_data_old = filesystem::data_path_old();
        
        /**
         * Get the old path contents.
         */
        auto path_contents_old = filesystem::path_contents(path_data_old);
        
        /**
         * If we have contents we need to migrate.
         */
        if (path_contents_old.size() > 0)
        {
            for (auto & i : path_contents_old)
            {
                /**
                 * Skip files we do not care about.
                 */
                if (i == "." || i == "..")
                {
                    continue;
                }
                
                log_info("Stack environment migrating " << i << ".");
                
                /**
                 * Rename the file to the new path.
                 */
                auto rc = std::rename(
                    (path_data_old + i).c_str(), (path_data + i).c_str()
                );
                
                if (rc)
                {
                    log_error(
                        "Stack environment migrate rename " << i << " failed."
                    );
                }
                else
                {
                    log_info(
                        "Stack environment migrate rename " << i << " success"
                    );
                }
            }
        }
#endif
    }
    else
    {
        throw std::runtime_error("failed to create path " + path_data);
    }
    
    /**
     * Create backups directory.
     */
    result = filesystem::create_path(path_data + "backups/");
    
    if (result == 0 || result == filesystem::error_already_exists)
    {
        log_none("Stack, " + path_data + "backups/ already exists.");
    }
    else
    {
        // ...
    }
    
    /**
     * Create blockchain directory.
     */
    if (globals::instance().is_client_spv() == false)
    {
        path_data = path_data + "blockchain/";
        
        log_info("Stack creating path = " << path_data << ".");
        
        result = filesystem::create_path(path_data);
        
        if (result == 0 || result == filesystem::error_already_exists)
        {
            log_none("Stack, path already exists.");
        }
        else
        {
            throw std::runtime_error("failed to create path " + path_data);
        }
            
        path_data += "peer/";
    }

    log_info("Stack creating path = " << path_data << ".");

    result = filesystem::create_path(path_data);
    
    if (result == 0 || result == filesystem::error_already_exists)
    {
        log_none("Stack, path already exists.");
    }
    else
    {
        throw std::runtime_error("failed to create path " + path_data);
    }
#if (defined __ANDROID__)
    /** 
     * Create the application data path on the sdcard.
     */
    filesystem::create_path(
        "/sdcard/Android/data/org.domain.app"
    );
#endif // __ANDROID__
}

void stack_impl::load_block_index(
    const std::function<void (const bool & success)> & f
    )
{
    /**
     * Thin clients (SPV) do not keep a block index.
     */
    if (globals::instance().is_client_spv() == true)
    {
        globals::instance().io_service().post(globals::instance().strand().wrap(
            [this, f]()
        {
            if (f)
            {
                f(true);
            }
        }));
    
        return;
    }
    
    /**
     * Load the block index by posting it to the boost::asio::io_service.
     */
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, f]()
    {
        /**
         * Load the block index.
         */
        db_tx tx_db("cr");
        
        if (tx_db.load_block_index(*this))
        {
            /**
             * Close the transaction database.
             */
            tx_db.close();

            /**
             * Initialize with the genesis block (if necessary).
             */
            if (globals::instance().block_indexes().size() == 0)
            {
                /**
                 * Create the genesis block.
                 */
                auto blk = block::create_genesis();
                
                /**
                 * Start new block file.
                 */
                std::uint32_t file_number;
                std::uint32_t block_position;
                
                if (blk.write_to_disk(file_number, block_position) == false)
                {
                    log_error(
                        "Load block index failed, writing genesis block to "
                        "disk failed."
                    );
                    
                    if (f)
                    {
                        f(false);
                    }
                }

                if (
                    blk.add_to_block_index(file_number, block_position) == false
                    )
                {
                    log_error(
                        "Load block index failed, genesis block not accepted"
                    );
                    
                    if (f)
                    {
                        f(false);
                    }
                }
            }

            if (f)
            {
                f(true);
            }

        }
        else
        {
            if (f)
            {
                f(false);
            }
        }
    }));
}

void stack_impl::load_wallet(
    const std::function<void (const bool & first_run,
    const db_wallet::error_t & err)> & f
    )
{
    auto first_run = true;

    globals::instance().set_wallet_main(std::make_shared<wallet> (*this));
    
    db_wallet::error_t ret =
        globals::instance().wallet_main()->load_wallet(first_run)
    ;
    
    if (f)
    {
        f(first_run, ret);
    }
}

void stack_impl::backup_last_wallet_file()
{
    auto path_backups = filesystem::data_path() + "backups/";
    
    auto contents = filesystem::path_contents(path_backups);
    
    /**
     * Erase anything that starts with ".".
     */
    auto it = contents.begin();
    
    while (it != contents.end())
    {
        const auto & val = *it;
        
        if (val.size() > 0 && val[0] == '.')
        {
            it = contents.erase(it);
        }
        else
        {
            ++it;
        }
    }
    
    if (contents.size() > 0)
    {
        std::map<std::time_t, std::string> wallets_sorted_by_time;
        
        std::time_t time_latest = 0;
        
        for (auto & i : contents)
        {
            if (
                i.find("wallet") == std::string::npos &&
                i.find(".dat") == std::string::npos
                )
            {
                continue;
            }
            
            std::vector<std::string> parts;
            
            boost::split(parts, i, boost::is_any_of("."));
            
            if (parts.size() == 3)
            {
                std::time_t time;
                
                /**
                 * Android does not implement std::atoll.
                 */
#if (defined __ANDROID__)
                time =
                    boost::lexical_cast<std::int64_t> (parts[1].c_str())
                ;
#else
                time = std::atoll(parts[1].c_str());
#endif // __ANDROID__

                /**
                 * We only perform a delete if the latest file is at least one
                 * day old.
                 */
                if (std::time(0) - time > 24 * 60 * 60)
                {
                    wallets_sorted_by_time[time] = i;
                }
                
                if (time > time_latest)
                {
                    time_latest = time;
                }
            }
        }
        
        /**
         * Keep at most 12 (automatic) backup wallet files.
         */
        enum { minimum_to_keep = 12 };

        if (wallets_sorted_by_time.size() >= minimum_to_keep)
        {
            auto path_to_remove = wallets_sorted_by_time.begin()->second;
            
            if (file::remove(path_backups + "/" + path_to_remove))
            {
                log_info(
                    "Stack removed old wallet backup " << path_to_remove << "."
                );
            }
            
            if (std::time(0) - time_latest > 24 * 60 * 60)
            {
                /**
                 * Backup the wallet.
                 */
                if (
                    std::ifstream(filesystem::data_path() + "wallet.dat").good()
                    )
                {
                    if (
                        filesystem::copy_file(filesystem::data_path() +
                        "wallet.dat", path_backups +  "wallet." +
                        std::to_string(std::time(0)) + ".dat") == true
                        )
                    {
                        log_info(
                            "Stack backed up wallet to " << path_backups << "."
                        );
                    }
                }
            }
        }
        else if (
            wallets_sorted_by_time.size() > 0 &&
            std::time(0) - time_latest > 24 * 60 * 60
             )
        {
            /**
             * Backup the wallet.
             */
            if (std::ifstream(filesystem::data_path() + "wallet.dat").good())
            {
                if (
                    filesystem::copy_file(filesystem::data_path() +
                    "wallet.dat", path_backups +  "wallet." +
                    std::to_string(std::time(0)) + ".dat") == true
                    )
                {
                    log_info(
                        "Stack backed up wallet to " << path_backups << "."
                    );
                }
            }
        }
        else
        {
            log_info("Stack doesn't need to backup wallet file, too soon.");
        }
    }
    else
    {
        /**
         * Backup the wallet.
         */
        if (std::ifstream(filesystem::data_path() + "wallet.dat").good())
        {
            if (
                filesystem::copy_file(filesystem::data_path() +
                "wallet.dat", path_backups +  "wallet." +
                std::to_string(std::time(0)) + ".dat") == true
                )
            {
                log_info(
                    "Stack backed up wallet to " << path_backups << "."
                );
            }
        }
    }
}

void stack_impl::lock_file_or_exit()
{
#if (! defined _MSC_VER && ! defined __IPHONE_OS_VERSION_MAX_ALLOWED && \
    ! defined __ANDROID__)
    static file f;
    
    if (
        f.open((filesystem::data_path() + ".lock").c_str(), "a") == false
        )
    {
        printf(
            "Unable to open lock file %s\n",
            (filesystem::data_path() + ".lock").c_str()
        );

        exit(0);
    }
    else
    {
        auto result = flock(fileno(f.get_FILE()), LOCK_EX | LOCK_NB);
        
        if (result == 0)
        {
            std::string pid = std::to_string(getpid());
        
            f.write(pid.data(), pid.size());
            
            f.fflush();
        }
        else
        {
            printf(
                "Failed to obtain lock on file %s\n",
                (filesystem::data_path() + ".lock").c_str()
            );
            
            exit(0);
        }
    }
#endif // _MSC_VER
}

bool stack_impl::export_blockchain_file()
{
    auto path_concat = filesystem::data_path() + "blockchain.dat";
    
    std::shared_ptr<file> f;
    
    std::ofstream ofs(
        path_concat, std::ios_base::binary | std::ios_base::app
    );
    
    auto file_index = 1;
    
    auto loop = true;
    
    do
    {
        auto path = block::get_file_path(file_index++);
        
        std::ifstream ifs(path, std::ios_base::binary | std::ios_base::in);
        
        if (ifs.good() && ifs.is_open())
        {
            log_info(
                "Stack (import blockchain) is concating path = " << path << "."
            );
            
            ofs << ifs.rdbuf();
            
            ofs.flush();
            
            ifs.close();
        }
        else
        {
            loop = false;
            
            break;
        }
    } while (
        loop && globals::instance().state() == globals::state_started
    );

    ofs.close();

    return true;
}

bool stack_impl::import_blockchain_file(const std::string & path)
{
    file f;

    std::uint32_t blocks_loaded = 0;
    
    if (f.open(path.c_str(), "rb") == true)
    {
        try
        {
            std::int32_t offset = 0;
            
            while (
                offset != std::numeric_limits<std::uint32_t>::max() &&
                globals::instance().state() == globals::state_started
                )
            {
                char buf[65536];
                
                do
                {
                    f.seek_set(offset);
                
                    std::size_t bytes_read = sizeof(buf);
                
                    if (f.read(buf, bytes_read) == true)
                    {
                        if (bytes_read <= 8)
                        {
                            offset = std::numeric_limits<std::uint32_t>::max();
                            
                            break;
                        }

                        void * magic_ptr = std::memchr(
                            buf, message::header_magic_bytes()[0],
                            bytes_read + 1 - message::header_magic_length
                        );
                        
                        if (magic_ptr)
                        {
                            if (
                                std::memcmp(magic_ptr,
                                &message::header_magic_bytes()[0],
                                message::header_magic_length) == 0
                                )
                            {
                                offset +=
                                    reinterpret_cast<std::uint8_t *> (
                                    magic_ptr) - reinterpret_cast<
                                    std::uint8_t *> (buf) +
                                    message::header_magic_length;
                                
                                break;
                            }
                            
                            offset +=
                                reinterpret_cast<std::uint8_t *> (
                                magic_ptr) - reinterpret_cast<
                                std::uint8_t *> (buf) + 1
                            ;
                        }
                        else
                        {
                            offset +=
                                sizeof(buf) - message::header_magic_length + 1
                            ;
                        }
                        
                    }
                    else
                    {
                        offset = std::numeric_limits<std::uint32_t>::max();
                        
                        break;
                    }
                
                } while (globals::instance().state() == globals::state_started);
                
                if (offset == std::numeric_limits<std::uint32_t>::max())
                {
                    break;
                }
                
                f.seek_set(offset);
                
                std::uint32_t len = 0;
                
                if (
                    f.read(
                    reinterpret_cast<char *> (&len), sizeof(len)) == true
                    )
                {
                    if (len > 0)
                    {
                        data_buffer buffer(len);
                        
                        if (f.read(buffer.data(), buffer.size()) == true)
                        {
                            std::shared_ptr<block> blk(new block());
                            
                            if (blk->decode(buffer) == true)
                            {
                                if (process_block(0, blk) == true)
                                {
                                    blocks_loaded++;
                                    
                                    offset +=
                                        message::header_magic_length + len
                                    ;
                                    
                                    if (blocks_loaded % 1 == 0)
                                    {
                                        /**
                                         * Allocate the status.
                                         */
                                        std::map<std::string, std::string>
                                            status
                                        ;
                                        
                                        /**
                                         * Set the status type.
                                         */
                                        status["type"] = "database";
                                    
                                        /**
                                         * Set the status value.
                                         */
                                        status["value"] =
                                            "Importing blockchain..."
                                        ;
                                        
                                        /**
                                         * Set the status value.
                                         */
                                        status["blockchain.import"] =
                                            std::to_string(blocks_loaded)
                                        ;

                                        /**
                                         * Callback
                                         */
                                        m_status_manager->insert(status);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    break;
                }
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "Stack failed importing blockchain file, what = " <<
                e.what() << "."
            );
        }
    }
    
    log_info("Stack imported " << blocks_loaded << " from blockchain file.");
    
    return blocks_loaded != 0;
}

void stack_impl::loop()
{
    while (
        globals::instance().state() == globals::state_starting ||
        globals::instance().state() == globals::state_started
        )
    {
        try
        {
            globals::instance().io_service().run();
            
            if (work_ == nullptr)
            {
                break;
            }
        }
        catch (const boost::system::system_error & e)
        {
            // ...
        }
    }
}

void stack_impl::loop_network()
{
    while (
        globals::instance().state() == globals::state_starting ||
        globals::instance().state() == globals::state_started
        )
    {
        try
        {
            io_service_network_.run();
            
            if (work_network_ == nullptr)
            {
                break;
            }
        }
        catch (const boost::system::system_error & e)
        {
            // ...
        }
    }
}

void stack_impl::do_check_peers(const std::uint32_t & interval)
{
    if (constants::test_net == false)
    {
        log_debug("Stack is checking peers.");
        
        url_get("http://bitcoin.com/p/",
            [this]
            (const std::map<std::string, std::string> & headers,
            const std::string & body
            )
        {
            if (headers.size() > 0 && body.size() > 0)
            {
                std::stringstream ss;

                ss << body;

                boost::property_tree::ptree pt;
                
                std::map<std::string, std::string> result;
                
                try
                {
                    read_json(ss, pt);

                    auto & pos = pt.get_child("peers");
                    
                    std::for_each(
                        std::begin(pos), std::end(pos),
                        [this](
                        boost::property_tree::ptree::value_type & pair
                        )
                    {
                        std::vector<std::string> parts;
                        
                        std::string endpoint =
                            pair.second.get<std::string> ("")
                        ;
                        
                        boost::split(
                            parts, endpoint, boost::is_any_of(":")
                        );
                        
                        auto ip = parts[0];
                        
                        auto port = parts[1];

                        log_debug(
                            "Stack got peer endpoint = " << ip << ":" <<
                            port << "."
                        );
                        
                        /**
                         * Create the network address.
                         */
                        protocol::network_address_t addr =
                            protocol::network_address_t::from_endpoint(
                            boost::asio::ip::tcp::endpoint(
                            boost::asio::ip::address::from_string(ip.c_str()),
                            std::stoi(port))
                        );
                        
                        /**
                         * Add to the address manager.
                         */
                        if (m_address_manager->add(
                            addr, protocol::network_address_t::from_endpoint(
                            boost::asio::ip::tcp::endpoint(
                            boost::asio::ip::address::from_string(
                            "127.0.0.1"), 0)))
                            )
                        {
                            log_debug(
                                "Stack added bootstrap peer " << ip << ":" <<
                                port << " to the address manager."
                            );
                        }
                    });
                }
                catch (std::exception & e)
                {
                    // ...
                }
            }
            else
            {
                // ...
            }
        });
    }
}
