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

#include <cassert>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <vector>

#include <coin/block.hpp>
#include <coin/block_index_disk.hpp>
#include <coin/checkpoints.hpp>
#include <coin/coins_cache.hpp>
#include <coin/data_buffer.hpp>
#include <coin/db_env.hpp>
#include <coin/db_tx_ldb.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/point_out.hpp>
#include <coin/sha256.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_pool.hpp>

#if (defined USE_LEVELDB && USE_LEVELDB)
#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#endif // USE_LEVELDB

using namespace coin;

#if (defined USE_LEVELDB && USE_LEVELDB)

/**
 * The (global) leveldb::DB.
 */
leveldb::DB * db_tx::g_leveldbDB = nullptr;

/**
 * The (global) leveldb::DB cache size.
 */
std::size_t db_tx::g_leveldb_cache_size = 25;

/**
 * The (global) leveldb::Options.
 */
static leveldb::Options leveldbOptions()
{
    leveldb::Options ret;

    auto cache_size = db_tx::leveldb_cache_size();

    ret.block_cache = leveldb::NewLRUCache(cache_size * 1024 * 1024);
    ret.filter_policy = leveldb::NewBloomFilterPolicy(10);
    ret.compression = leveldb::kNoCompression;
    ret.max_open_files = 64;
    
    if (
    	leveldb::kMajorVersion > 1 ||
        (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)
        )
    {
        ret.paranoid_checks = true;
    }
    
    return ret;
}

db_tx::db_tx(const std::string & file_mode)
    : m_version(current_version)
    , m_leveldbDB(0)
    , m_leveldbWriteBatch(0)
    , m_leveldbWriteOptions()
{
    auto read_only =
        (!strchr(file_mode.c_str(), '+') && !strchr(file_mode.c_str(), 'w'))
    ;

    if (g_leveldbDB)
    {
        m_leveldbDB = g_leveldbDB;
        
        return;
    }

    auto should_create = strchr(file_mode.c_str(), 'c');

    m_leveldbWriteOptions = leveldbOptions();
    m_leveldbWriteOptions.create_if_missing = should_create;
    m_leveldbWriteOptions.filter_policy = leveldb::NewBloomFilterPolicy(10);

    /**
     * Get the data path.
     */
    auto path_database = filesystem::data_path() + "txleveldb/";
    
    filesystem::create_path(path_database);
    
    log_info(
    	"Transaction database (leveldb) initializing, path = " <<
        path_database << "."
    );
    
    /**
     * @note Verify that we do not need to first convert the filesystem path
     * from multi-byte to wide char and back on Windows OS like with BDB.
     */
    
    auto status = leveldb::DB::Open(
        m_leveldbWriteOptions, path_database, &g_leveldbDB
    );
    
    if (status.ok() == false)
    {
        throw std::runtime_error(
        	"Transaction database (leveldb) initialization failed, status = " +
            status.ToString()
        );
    }
    
    m_leveldbDB = g_leveldbDB;

    if (exists("version") == true)
    {
        read_version();
		
        log_info(
             "Transaction database (leveldb) version = " << m_version << "."
        );
        
        if (m_version < current_version)
        {
            log_info(
				"Transaction database (leveldb) version = " <<
                current_version << ", removing old database."
            );
        
            delete g_leveldbDB, g_leveldbDB = m_leveldbDB = 0;
            delete m_leveldbWriteBatch, m_leveldbWriteBatch = 0;

            file::remove(path_database);
            
            filesystem::create_path(path_database);

			log_info(
         		"Transaction database (leveldb) initializing, path = " <<
                 path_database << "."
            );
            
            auto status = leveldb::DB::Open(
                m_leveldbWriteOptions, path_database, &g_leveldbDB
            );
            
            if (status.ok() == false)
            {
                throw std::runtime_error(
                    "Transaction database (leveldb) initialization failed, "
                    "status = " + status.ToString()
                );
            }
            
            m_leveldbDB = g_leveldbDB;

            auto was_read_only = read_only;
            
            read_only = false;

            write_version();
            
            read_only = was_read_only;
        }
    }
    else if (should_create)
    {
        auto was_read_only = read_only;
        
        read_only = false;

        write_version();
        
        read_only = was_read_only;
    }

    log_info("Transaction database (leveldb) initialized.");
}

db_tx::~db_tx()
{
    // ...
}

bool db_tx::txn_begin()
{
    assert(!m_leveldbWriteBatch);
    
    m_leveldbWriteBatch = new leveldb::WriteBatch();
    
    return true;
}

bool db_tx::txn_commit()
{
    assert(m_leveldbWriteBatch);
    
    leveldb::Status status = m_leveldbDB->Write(
        leveldb::WriteOptions(), m_leveldbWriteBatch
    );
    
    delete m_leveldbWriteBatch, m_leveldbWriteBatch = 0;
    
    if (status.ok() == false)
    {
    	log_error(
        	"Transaction database (leveldb) batch commit failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }
    
    return true;
}

bool db_tx::txn_abort()
{
    delete m_leveldbWriteBatch, m_leveldbWriteBatch = nullptr;
    
    return true;
}

void db_tx::close()
{
	// ...
}

bool db_tx::load_block_index(stack_impl & impl)
{
    if (load_block_index_guts(impl))
    {
        /**
         * Calculate chain trust.
         */
        std::vector<
            std::pair<std::uint32_t, block_index *>
        > sorted_by_height;
        
        sorted_by_height.reserve(globals::instance().block_indexes().size());
        
        const auto & block_indexes = globals::instance().block_indexes();
        
        for (auto & i : block_indexes)
        {
            sorted_by_height.push_back(
                std::make_pair(i.second->height(), i.second)
            );
        }
        
        std::sort(sorted_by_height.begin(), sorted_by_height.end());
        
        for (auto & i : sorted_by_height)
        {
            try
            {
                i.second->m_chain_trust =
                    (i.second->block_index_previous() ?
                    i.second->block_index_previous()->m_chain_trust : 0) +
                    i.second->get_block_trust()
                ;
            }
            catch (std::exception & e)
            {
                log_error("DB TX, what = " << e.what() << ".");
                
                continue;
            }
        }

     	auto * block_index_best =
			coins_cache::instance().block_index_best()
        ;
        
        /**
         * We have only the genesis block.
         */
        if (block_index_best == nullptr)
        {
			return true;
        }
        
        globals::instance().set_hash_best_chain(
        	block_index_best->get_block_hash()
        );
        
        stack_impl::set_block_index_best(block_index_best);
        globals::instance().set_best_block_height(
            block_index_best->height()
        );
        stack_impl::get_best_chain_trust() =
            block_index_best->chain_trust()
        ;
        
        if (
            globals::instance().block_indexes().count(
            globals::instance().hash_best_chain()) == 0
            )
        {
            throw std::runtime_error(
                "best hash chain not found in the block index"
            );
            
            return false;
        }

        /**
         * If we are configured to perform headers first chain
         * synchronization then set the last block header in the
         * chain.
         */
        if (
            globals::instance().peer_use_headers_first_chain_sync(
            ) == true
            )
        {
            stack_impl::get_block_index_best()->get_block_header(
                ).set_peer_headers_first_sync_height(
                   stack_impl::get_block_index_best()->m_height
            );

            globals::instance().set_peer_headers_first_block_last(
                stack_impl::get_block_index_best()->get_block_header()
            );
            
            globals::instance().peer_headers_first_block_last(
                )->set_peer_headers_first_sync_height(
                stack_impl::get_block_index_best()->m_height
            );
        }
        
        log_debug(
            "DB TX hash best chain = " <<
            globals::instance().hash_best_chain().to_string() << ", height = " <<
            stack_impl::get_block_index_best()->m_height << ", trust = " <<
            stack_impl::get_block_index_best()->m_chain_trust.to_string() <<
            ", time = " << stack_impl::get_block_index_best()->m_time << "."
        );
        
        /**
         * Read the best invalid trust if it is found, okay if not found.
         */
        if (read_best_invalid_trust(stack_impl::get_best_invalid_trust()))
        {
            log_info(
                "DB TX read best invalid trust " <<
                stack_impl::get_best_invalid_trust().to_string() << "."
            );
        }
        
        /**
         * Verify the blocks in the best chain.
         * -checklevel (1-6)
         */
        enum { check_level = 3 };

        auto check_depth = 24;

        if (check_depth == 0)
        {
            check_depth = 1000000000;
        }
        
        if (check_depth > globals::instance().best_block_height())
        {
            check_depth = globals::instance().best_block_height();
        }
        
        log_info(
            "DB TX is verifying " << check_depth <<
            " blocks at level << " << check_level << "."
        );

        block_index * index_fork = 0;
        
        std::map<
            std::pair<std::uint32_t, std::uint32_t>, block_index *
        > block_positions;
        
        auto checked_blocks = 0;
        
        for (
            auto i = stack_impl::get_block_index_best();
            i && i->block_index_previous();
            i = i->block_index_previous()
            )
        {
            if (
                i->height() < globals::instance().best_block_height() -
                check_depth
                )
            {
                break;
            }
            
            /**
             * Allocate the block.
             */
            block blk;
            
            /**
             * Read the block from disk.
             */
            if (blk.read_from_disk(i))
            {
                float percentage =
                    ((float)checked_blocks / (float)check_depth) * 100.0f
                ;
                
                /**
                 * Only callback status every 100 blocks or 100%.
                 */
                if ((i->height() % 100) == 0 || percentage == 100.0f)
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
                     * The block download percentage.
                     */
                    status["blockchain.verify.percent"] =
                        std::to_string(percentage)
                    ;
        
                    /**
                     * Callback
                     */
                    impl.get_status_manager()->insert(status);
                }
                
                try
                {
                    /**
                     * Verify block validity.
                     */
                    if (check_level > 0 && blk.check_block() == false)
                    {
                        log_error(
                            "DB TX Found bad block at " << i->m_height <<
                            ", hash = " << i->get_block_hash().to_string() << "."
                        );
                        
                        index_fork = i->block_index_previous();
                    }
                }
                catch (...)
                {
                    log_error(
                        "DB TX Found bad block at " << i->m_height <<
                        ", hash = " << i->get_block_hash().to_string() << "."
                    );
                    
                    index_fork = i->block_index_previous();
                }

                /**
                 * Increment the number of blocks we have checked in order to
                 * calculate the progress percentage.
                 */
                checked_blocks++;
                
                /**
                 * Verify transaction index validity.
                 */
                if (check_level > 1)
                {
                    auto position = std::make_pair(
                        i->m_file, i->m_block_position
                    );
                    
                    block_positions[position] = i;

                    for (auto & j : blk.transactions())
                    {
                        if (
                            globals::instance().state() >=
                            globals::state_stopping
                            )
                        {
                            log_debug(
                                "DB TX load is aborting, state >= "
                                "state_stopping."
                            );
                            
                            return false;
                        }
                        
                        /**
                         * Get the hash of the transaction.
                         */
                        auto hash_tx = j.get_hash();
                        
                        transaction_index tx_index;

                        if (read_transaction_index(hash_tx, tx_index))
                        {
                            /**
                             * Check transaction hashes.
                             */
                            if (
                                check_level > 2 ||
                                i->file() != tx_index.get_transaction_position(
                                ).file_index() ||
                                i->block_position() !=
                                tx_index.get_transaction_position(
                                ).block_position()
                                )
                            {
                                /**
                                 * Either an error or a duplicate transaction.
                                 */
                                transaction tx_found;

                                if (
                                    tx_found.read_from_disk(
                                    tx_index.get_transaction_position()
                                    ) == false
                                    )
                                {
                                    log_error(
                                        "DB TX cannot read mislocated "
                                        "transaction " <<
                                        hash_tx.to_string() << "."
                                    );

                                    /**
                                     * Fork
                                     */
                                    index_fork = i->block_index_previous();
                                }
                                else if (tx_found.get_hash() != hash_tx)
                                {
                                    log_error(
                                        "DB TX invalid transaction "
                                        "position for transaction " <<
                                        tx_found.get_hash().to_string() <<
                                        ":" << hash_tx.to_string() << "."
                                    );

                                    /**
                                     * Fork
                                     */
                                    index_fork = i->block_index_previous();
                                }
                            }
                        }
                        
                        /**
                         * Check whether spent transaction outs were spent
                         * within the main chain.
                         */
                        std::uint32_t output = 0;
                        
                        if (check_level > 3)
                        {
                            for (auto & k : tx_index.spent())
                            {
                                if (k.is_null() == false)
                                {
                                    auto find = std::make_pair(
                                        k.file_index(), k.block_position()
                                    );
                                    
                                    if (block_positions.count(find) == 0)
                                    {
                                        log_error(
                                            "DB TX found bad spend at " <<
                                            i->m_height << "."
                                        );

                                        index_fork =
                                            i->block_index_previous()
                                        ;
                                    }
                                    
                                    /**
                                     * Check level 6 checks if spent transaction
                                     * outs were spent by a valid transaction
                                     * that consume them.
                                     */
                                    if (check_level > 5)
                                    {
                                        transaction tx_spend;
                                        
                                        if (tx_spend.read_from_disk(k) == false)
                                        {
                                            log_error(
                                                "DB TX cannot read spending "
                                                "transaction " <<
                                                hash_tx.to_string() << ":" <<
                                                output << " from disk."
                                            );

                                            index_fork =
                                                i->block_index_previous()
                                            ;
                                        }
                                        else if (tx_spend.check() == false)
                                        {
                                            log_error(
                                                "DB TX got invalid spending "
                                                "transaction " <<
                                                hash_tx.to_string() << ":" <<
                                                output << "."
                                            );

                                            index_fork =
                                                i->block_index_previous()
                                            ;
                                        }
                                        else
                                        {
                                            bool found = false;
                                            
                                            for (
                                                auto & l :
                                                tx_spend.transactions_in()
                                                )
                                            {
                                                if (
                                                    l.previous_out().get_hash()
                                                    == hash_tx &&
                                                    l.previous_out().n()
                                                    == output
                                                    )
                                                {
                                                    found = true;
                                                    
                                                    break;
                                                }
                                            }
                                            
                                            if (found == false)
                                            {
                                                log_error(
                                                    "DB TX spending "
                                                    "transaction " <<
                                                    hash_tx.to_string() <<
                                                    ":" << output << " does "
                                                    "not spend it."
                                                );

                                                index_fork =
                                                    i->block_index_previous()
                                                ;
                                            }
                                        }
                                    }
                                }
                                
                                output++;
                            }
                        }
                        
                        /**
                         * Check level 5 checks if all previous outs are
                         * marked spent.
                         */
                        if (check_level > 4)
                        {
                            for (auto & k : j.transactions_in())
                            {
                                transaction_index tx_index;
                                
                                if (
                                    read_transaction_index(
                                    k.previous_out().get_hash(), tx_index)
                                    )
                                {
                                    if (
                                        tx_index.spent().size() - 1 <
                                        k.previous_out().n() ||
                                        tx_index.spent()[
                                        k.previous_out().n()].is_null()
                                        )
                                    {
                                        log_error(
                                            "DB TX found unspent previous "
                                            "out " <<
                                            k.previous_out().get_hash().to_string()
                                            << ":" << k.previous_out().n() <<
                                            " in " << hash_tx.to_string() << "."
                                        );
                                        
                                        index_fork = i->block_index_previous();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                log_error("Block failed to read block from disk.");
            
                return false;
            }
        }

        if (index_fork)
        {
            log_info(
                "DB TX is moving best chain pointer back to block " <<
                index_fork->m_height << "."
            );
            
            block b;
            
            if (b.read_from_disk(index_fork) == false)
            {
                log_error("Block failed to read (index fork) block from disk.");
            
                return false;
            }
            
            /**
             * Allocate the db_tx.
             */
            db_tx dbtx;

            /**
             * Set the best chain.
             */
            b.set_best_chain_2(dbtx, index_fork);
        }
        
        return true;
    }
    
    return false;
}

bool db_tx::contains_transaction(const sha256 & hash)
{
    std::string key_tx = "tx";
    
    data_buffer buffer;

    buffer.write_var_int(key_tx.size());
    buffer.write_bytes(key_tx.data(), key_tx.size());
    
    buffer.write_sha256(hash);
    
    return exists(buffer);
}

bool db_tx::read_version()
{
    std::string key = "version";
    
    std::string value_str;
    
    auto should_read_from_db = true;
    
    if (m_leveldbWriteBatch)
    {
        auto deleted = false;
        
        should_read_from_db = scan_batch(
            data_buffer(key.data(), key.size()), value_str, deleted
        ) == false;
        
        if (deleted == true)
        {
            return false;
        }
    }
    
    if (should_read_from_db == true)
    {
        auto status = m_leveldbDB->Get(leveldb::ReadOptions(), key, &value_str);
        
        if (status.ok() == false)
        {
            if (status.IsNotFound())
            {
                return false;
            }
            
            log_error(
                "Transaction database (leveldb) read failed, status = " <<
                status.ToString() << "."
            );
            
            return false;
        }
    }
    
    if (value_str.size() >= sizeof(m_version))
    {
        std::memcpy(&m_version, value_str.data(), sizeof(m_version));
    }
    
    return true;
}

bool db_tx::write_version()
{
    std::string key = "version";
    
    data_buffer key_data;

    key_data.write_var_int(key.size());
    key_data.write((void *)key.data(), key.size());
    
    data_buffer value_data;
    
    value_data.write_uint32(current_version);
    
    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );
    std::string value_str(
        value_data.data(), value_data.data() + value_data.size()
    );
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Put(key_str, value_str);
        
        return true;
    }

    leveldb::Status status = m_leveldbDB->Put(
        leveldb::WriteOptions(), key_str, value_str
    );

    if (status.ok() == false)
    {
        log_error(
            "Transaction database (leveldb) write failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }

    return true;
}

bool db_tx::read_disk_transaction(
    const sha256 & hash, transaction & tx, transaction_index & index
    )
{
    assert(globals::instance().is_client_spv() == false);
    
    tx.set_null();
    
    if (read_transaction_index(hash, index) == false)
    {
        return false;
    }
    
    return tx.read_from_disk(index.get_transaction_position());
}

bool db_tx::read_disk_transaction(const sha256 & hash, transaction & tx)
{
    transaction_index index;
    
    return read_disk_transaction(hash, tx, index);
}

bool db_tx::read_disk_transaction(
    const point_out & outpoint, transaction & tx, transaction_index & index
    )
{
    return read_disk_transaction(outpoint.get_hash(), tx, index);
}

bool db_tx::read_disk_transaction(const point_out & outpoint, transaction & tx)
{
    transaction_index index;
    
    return read_disk_transaction(outpoint.get_hash(), tx, index);
}

bool db_tx::read_transaction_index(
    const sha256 & hash, transaction_index & index
    )
{
    index.set_null();
    
    std::string key_tx = "tx";
    
    data_buffer buffer;

    buffer.write_var_int(key_tx.size());
    buffer.write_bytes(key_tx.data(), key_tx.size());
    
    buffer.write_sha256(hash);
    
    return read(buffer, index);
}

bool db_tx::update_transaction_index(
    const sha256 & hash, transaction_index & index
    )
{
    return write(std::make_pair(std::string("tx"), hash), index);
}

bool db_tx::erase_transaction_index(const transaction & tx) const
{
    std::string key_tx = "tx";
    
    data_buffer buffer;

    buffer.write_var_int(key_tx.size());
    buffer.write_bytes(key_tx.data(), key_tx.size());
    
    buffer.write_sha256(tx.get_hash());

    return erase(buffer);
}

bool db_tx::write_hash_best_chain(const sha256 & hash)
{
    return write_sha256("hashBestChain", hash);
}

bool db_tx::write_best_invalid_trust(big_number & bn)
{
    return write(std::string("bnBestInvalidTrust"), bn);
}

bool db_tx::load_block_index_guts(stack_impl & impl)
{
    auto * it = m_leveldbDB->NewIterator(leveldb::ReadOptions());
    
    /**
     * Read the next record.
     */
    data_buffer key, value;

    key.write_var_int(strlen("blockindex"));
    key.write((void *)"blockindex", strlen("blockindex"));
    char null_digest[32] = { '\0' };
    key.write(null_digest, sizeof(null_digest));
    
    it->Seek(std::string(key.data(), key.data() + key.size()));
    
    while (it->Valid() == true)
    {
        if (globals::instance().state() >= globals::state_stopping)
        {
            log_debug(
                "DB TX load block index is aborting, state >= "
                "state_stopping."
            );
            
            delete it;
            
            return false;
        }
        
        try
        {
            key.clear();
            value.clear();
            
            key.write_bytes(it->key().data(), it->key().size());
            value.write_bytes(it->value().data(), it->value().size());
            
            /**
             * Read the key out length.
             */
            auto key_out_len = key.read_var_int();
            
            /**
             * Read the key out.
             */
            std::string key_out(key.data() + 1, key_out_len);

            if (key_out == "blockindex")
            {
                /**
                 * Allocate the block index disk.
                 */
                block_index_disk index_disk(value.data(), value.size());
                
                /**
                 * Decode the block index from disk.
                 */
                index_disk.decode();
                
                /**
                 * Allocate a block index object.
                 */
                const auto & index_new = stack_impl::insert_block_index(
                    index_disk.get_block_hash()
                );

                index_new->set_block_index_previous(
                    stack_impl::insert_block_index(
                    index_disk.m_hash_previous)
                );

                index_new->m_block_index_next =
                    stack_impl::insert_block_index(
                    index_disk.m_hash_next
                );
                
                index_new->m_file = index_disk.m_file;

                index_new->m_block_position = index_disk.m_block_position;
                index_new->m_height = index_disk.m_height;
                index_new->m_mint = index_disk.m_mint;
                index_new->m_money_supply = index_disk.m_money_supply;
                index_new->m_flags = index_disk.m_flags;
                index_new->m_version = index_disk.m_version;
                index_new->m_hash_merkle_root =
                    index_disk.m_hash_merkle_root
                ;
                index_new->m_time = index_disk.m_time;
                index_new->m_bits = index_disk.m_bits;
                index_new->m_nonce = index_disk.m_nonce;

                /**
                 * Only callback status every 2016 blocks.
                 */
                if ((index_new->m_height % 2016) == 0)
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
                     * Set the status value.
                     */
                    status["value"] =
                        "Loading block indexes (" +
                        std::to_string(index_new->m_height) +
                        ")..."
                    ;

                    /**
                     * Callback
                     */
                    impl.get_status_manager()->insert(status);
                }
                
                /**
                 * Check for the genesis block.
                 */
                if (
                    stack_impl::get_block_index_genesis() == 0 &&
                    index_disk.get_block_hash() ==
                    (constants::test_net ?
                    block::get_hash_genesis_test_net() :
                    block::get_hash_genesis())
                    )
                {
                    log_info("Database transaction got genesis block.");
                
                    stack_impl::set_block_index_genesis(index_new);
                }
            }
            else
            {
                break;
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "Database transaction failed loading block index guts, "
                "what = " << e.what() << "."
            );
            
            delete it;
            
            return false;
        }
        
        it->Next();
    }

	delete it;
	
    /**
     * If we are configured to perform headers first chain
     * synchronization then insert each block header into the
     * peer_headers_first_blocks map.
     */
    if (
        globals::instance().peer_use_headers_first_chain_sync(
        ) == true
        )
    {
        for (auto & i : globals::instance().block_indexes())
        {
             i.second->get_block_header().set_peer_headers_first_sync_height(
                 i.second->height()
            );
            
            globals::instance().peer_headers_first_blocks()[
                i.second->get_block_hash()].reset(
                new block(i.second->get_block_header())
            );
            
            globals::instance().peer_headers_first_blocks()[
                i.second->get_block_hash()
            ]->set_peer_headers_first_sync_height(i.second->height());
            
            /**
             * Map the block header height to the hash.
             */
            globals::instance().peer_headers_first_heights_and_hashes()[
                i.second->height()] = i.second->get_block_hash()
            ;
        }
    }
    
	return true;
}

bool db_tx::read_best_hash_chain(sha256 & hash)
{
    return read_sha256("hashBestChain", hash);
}

bool db_tx::write_blockindex(block_index_disk value)
{
    return write(
        std::make_pair(std::string("blockindex"), value.get_block_hash()), value
    );
}

bool db_tx::read_best_invalid_trust(big_number & bn)
{
    return read_big_number("bnBestInvalidTrust", bn);
}

bool db_tx::read_string(const std::string & key, std::string & val)
{
    auto should_read_from_db = true;
    
    if (m_leveldbWriteBatch)
    {
        auto deleted = false;
        
        should_read_from_db = scan_batch(
            data_buffer(key.data(), key.size()), val, deleted
        ) == false;
        
        if (deleted == true)
        {
            return false;
        }
    }
    
    if (should_read_from_db == true)
    {
        auto status = m_leveldbDB->Get(leveldb::ReadOptions(), key, &val);
        
        if (status.ok() == false)
        {
            if (status.IsNotFound())
            {
                return false;
            }
            
            log_error(
                "Transaction database (leveldb) read failed, status = " <<
                status.ToString() << "."
            );
            
            return false;
        }
    }
    
    return true;
}

bool db_tx::write_string(
    const std::string & key, const std::string & value, const bool & overwrite
    )
{
    data_buffer key_data;

    key_data.write_var_int(key.size());
    key_data.write((void *)key.data(), key.size());
    
    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );
    std::string value_str = value;
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Put(key_str, value_str);
        
        return true;
    }

    leveldb::Status status = m_leveldbDB->Put(
        leveldb::WriteOptions(), key_str, value_str
    );

    if (status.ok() == false)
    {
        log_error(
            "Transaction database (leveldb) write failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }

    return true;
}

bool db_tx::read_sha256(const std::string & key, sha256 & value)
{
    data_buffer key_data;

    key_data.write_var_int(key.size());
    key_data.write((void *)key.c_str(), key.size());
    
    std::string value_str;
    
    auto should_read_from_db = true;
    
    if (m_leveldbWriteBatch)
    {
        auto deleted = false;
        
        should_read_from_db = scan_batch(
            key_data, value_str, deleted
        ) == false;
        
        if (deleted == true)
        {
            return false;
        }
    }
    
    if (should_read_from_db == true)
    {
        auto status = m_leveldbDB->Get(
            leveldb::ReadOptions(), std::string(key_data.data(),
            key_data.data() + key_data.size()), &value_str
        );
        
        if (status.ok() == false)
        {
            if (status.IsNotFound())
            {
                return false;
            }
            
            log_error(
                "Transaction database (leveldb) read failed, status = " <<
                status.ToString() << "."
            );
        
            return false;
        }
    }
    
    if (value_str.size() >= sha256::digest_length)
    {
        std::memcpy(
            (void *)value.digest(), value_str.data(), sha256::digest_length
        );
    }
    
    return true;
}

bool db_tx::write_sha256(
    const std::string & key, const sha256 & value, const bool & overwrite
    )
{
    data_buffer key_data;

    key_data.write_var_int(key.size());
    key_data.write((void *)key.data(), key.size());
    
    data_buffer value_data;

    value_data.write_sha256(value);
    
    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );
    std::string value_str(
        value_data.data(), value_data.data() + value_data.size()
    );
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Put(key_str, value_str);
        
        return true;
    }

    leveldb::Status status = m_leveldbDB->Put(
        leveldb::WriteOptions(), key_str, value_str
    );

    if (status.ok() == false)
    {
        log_error(
            "Transaction database (leveldb) write failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }

    return true;
}

bool db_tx::read_big_number(const std::string & key, big_number & value)
{
    std::string value_str;
    
    auto should_read_from_db = true;
    
    if (m_leveldbWriteBatch)
    {
        auto deleted = false;
        
        should_read_from_db = scan_batch(
            data_buffer(key.data(), key.size()), value_str, deleted
        ) == false;
        
        if (deleted == true)
        {
            return false;
        }
    }
    
    if (should_read_from_db == true)
    {
        auto status = m_leveldbDB->Get(
            leveldb::ReadOptions(), key, &value_str
        );
        
        if (status.ok() == false)
        {
            if (status.IsNotFound())
            {
                return false;
            }
            
            log_error(
                "Transaction database (leveldb) read failed, status = " <<
                status.ToString() << "."
            );
            
            return false;
        }
    }

    value.set_vector(
        {(std::uint8_t *)value_str.data(),
        (std::uint8_t *)value_str.data() + value_str.size()}
    );
    
    return true;
}

template<typename T>
bool db_tx::read(const data_buffer & key, T & value)
{
    std::string key_str(key.data(), key.data() + key.size());

    std::string value_str;

    auto should_read_from_db = true;
    
    if (m_leveldbWriteBatch)
    {
        auto deleted = false;
        
        should_read_from_db = scan_batch(key, value_str, deleted) == false;
        
        if (deleted == true)
        {
            log_error(
            	"Transaction database (leveldb) read failed (deleted)."
            );
            
            return false;
        }
    }

    if (should_read_from_db == true)
    {
        auto status = m_leveldbDB->Get(
            leveldb::ReadOptions(), key_str, &value_str
        );
        
        if (status.ok() == false)
        {
            if (status.IsNotFound())
            {
                return false;
            }

            log_error(
                "Transaction database (leveldb) read failed, status = " <<
                status.ToString() << "."
            );
        
            return false;
        }
    }

    try
    {
        /**
         * Allocate the data_buffer.
         */
        data_buffer buffer(value_str.data(), value_str.size());
        
        /**
         * Decode the value from the buffer.
         */
        value.decode(buffer);
    }
    catch (std::exception & e)
    {
        log_error(
            "Transaction database (leveldb) read failed, what = " <<
            e.what() << "."
        );
        
        return false;
    }
    
    return true;
}

template<typename T1, typename T2>
bool db_tx::write(const T1 & key, T2 & value, const bool & overwrite)
{
    data_buffer key_data;

    key_data.write_var_int(key.size());
    key_data.write((void *)key.data(), key.size());
    
    data_buffer value_data;

    value.encode(value_data);
    
    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );
    std::string value_str(
        value_data.data(), value_data.data() + value_data.size()
    );
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Put(key_str, value_str);
        
        return true;
    }

    leveldb::Status status = m_leveldbDB->Put(
        leveldb::WriteOptions(), key_str, value_str
    );

    if (status.ok() == false)
    {
        log_error(
            "Transaction database (leveldb) write failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }

    return true;
}

template<typename T1>
bool db_tx::write(
    const std::pair<std::string, sha256> & key, T1 & value,
    const bool & overwrite
    )
{
    auto k1 = key.first;
    auto k2 = key.second;
    
    data_buffer key_data;

    key_data.write_var_int(k1.size());
    key_data.write_bytes(k1.data(), k1.size());
    key_data.write_sha256(k2);
    
    data_buffer value_data;

    value.encode(value_data);

    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );
    std::string value_str(
        value_data.data(), value_data.data() + value_data.size()
    );
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Put(key_str, value_str);
        
        return true;
    }

    leveldb::Status status = m_leveldbDB->Put(
        leveldb::WriteOptions(), key_str, value_str
    );

    if (status.ok() == false)
    {
        log_error(
            "Transaction database (leveldb) write failed, status = " <<
            status.ToString() << "."
        );
        
        return false;
    }

    return true;
}

bool db_tx::exists(const data_buffer & key)
{
    std::string value;
    
    if (m_leveldbWriteBatch)
    {
        bool deleted;

        if (scan_batch(key, value, deleted) && deleted == false)
        {
            return true;
        }
    }

    auto status =
        m_leveldbDB->Get(leveldb::ReadOptions(),
        std::string(key.data(), key.data() + key.size()), &value)
    ;
    
    return status.IsNotFound() == false;
}

bool db_tx::exists(const std::string & key)
{
    data_buffer buffer;

    buffer.write_var_int(key.size());
    buffer.write_bytes(key.data(), key.size());

    std::string value;
    
    if (m_leveldbWriteBatch)
    {
        bool deleted;

        if (scan_batch(buffer, value, deleted) && deleted == false)
        {
            return true;
        }
    }

    auto status =
        m_leveldbDB->Get(leveldb::ReadOptions(),
        std::string(buffer.data(), buffer.data() + buffer.size()), &value)
    ;
    
    return status.IsNotFound() == false;
}

bool db_tx::erase(const data_buffer & key) const
{
    if (m_leveldbDB == 0)
    {
        return false;
    }
    
    std::string key_str(key.data(), key.data() + key.size());
    
    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Delete(key_str);
        
        return true;
    }
    
    auto status = m_leveldbDB->Delete(leveldb::WriteOptions(), key_str);
    
    return status.ok() || status.IsNotFound();
}

bool db_tx::erase(
    const std::pair<std::string, std::vector<std::uint8_t> > & key
    ) const
{
    if (m_leveldbDB == 0)
    {
        return false;
    }

    auto k1 = key.first;
    auto k2 = key.second;
    
    data_buffer key_data;

    key_data.write_var_int(k1.size());
    key_data.write_bytes(k1.data(), k1.size());
    key_data.write_var_int(k2.size());
    key_data.write_bytes(
        reinterpret_cast<char *>(&k2[0]), k2.size()
    );
    
    std::string key_str(
        key_data.data(), key_data.data() + key_data.size()
    );

    if (m_leveldbWriteBatch)
    {
        m_leveldbWriteBatch->Delete(key_str);
        
        return true;
    }
    
    auto status = m_leveldbDB->Delete(leveldb::WriteOptions(), key_str);
    
    return status.ok() || status.IsNotFound();
}

bool db_tx::scan_batch(
    const data_buffer & key, std::string & value, bool & deleted
    ) const
{
    assert(m_leveldbWriteBatch);
    
    deleted = false;
    
    leveldbWriteBatchHandler scanner;
    
    scanner.set_needle(std::string(key.data(), key.data() + key.size()));
    scanner.set_deleted(deleted);
    scanner.set_value(value);
    
    leveldb::Status status = m_leveldbWriteBatch->Iterate(&scanner);
    
    if (status.ok() == false)
    {
        throw std::runtime_error(status.ToString());
    }
    
    return scanner.found_entry();
}

void db_tx::leveldb_close()
{
    delete db_tx::g_leveldbDB, db_tx::g_leveldbDB = nullptr;
}

void db_tx::set_leveldb_cache_size(const std::size_t & val)
{
	g_leveldb_cache_size = val;
}

const std::size_t & db_tx::leveldb_cache_size()
{
	return g_leveldb_cache_size;
}

#endif // USE_LEVELDB
