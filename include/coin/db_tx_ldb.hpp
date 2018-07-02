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

#ifndef COIN_DB_TX_LDB_HPP
#define COIN_DB_TX_LDB_HPP

#include <cstdint>
#include <string>

#include <boost/noncopyable.hpp>

#include <coin/big_number.hpp>
#include <coin/db.hpp>
#include <coin/db_tx.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_index.hpp>

#if (defined USE_LEVELDB && USE_LEVELDB)
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#endif // USE_LEVELDB

namespace coin {

#if (defined USE_LEVELDB && USE_LEVELDB)
    class block_index;
    class block_index_disk;
    class data_buffer;
    class point_out;
    class sha256;
    class stack_impl;
    class transaction;
    
    /**
     * Implements a transaction database.
     */
    class db_tx : private boost::noncopyable
    {
        public:
        
            /**
             * Implements a leveldb::WriteBatch::Handler.
             */
            class leveldbWriteBatchHandler
                : public leveldb::WriteBatch::Handler
            {
                public:
                
                    /**
                     * Constructor
                     */
                    leveldbWriteBatchHandler()
                        : m_deleted(false)
                        , m_found_entry(false)
                    {
                        // ...
                    }
                
                    /**
                     * Puts a key/value pair.
                     * @param key The key.
                     * @param value The value.
                     */
                    virtual void Put(
                        const leveldb::Slice & key,
                        const leveldb::Slice & value
                        )
                    {
                        if (key.ToString() == m_needle)
                        {
                            m_found_entry = true;
                            m_deleted = false;
                            m_value = value.ToString();
                        }
                    }

                    /**
                     * Deletes an entry given key.
                     * @param key The key.
                     */
                    virtual void Delete(const leveldb::Slice & key)
                    {
                        if (key.ToString() == m_needle)
                        {
                            m_found_entry = true;
                            m_deleted = true;
                        }
                    }
                
                    /**
                     * Sets the needle.
                     * @param val the value.
                     */
                    void set_needle(const std::string & val)
                    {
                        m_needle = val;
                    }
                
                    /**
                     * The needle.
                     */
                    const std::string & needle() const
                    {
                        return m_needle;
                    }
                
                    /**
                     * Sets the entr as deleted.
                     * @param val The value.
                     */
                    void set_deleted(const bool & val)
                    {
                        m_deleted = val;
                    }
                
                    /**
                     * Sets the value.
                     * @param val The value.
                     */
                    void set_value(const std::string & val)
                    {
                        m_value = val;
                    }
                
                    /**
                     * If true the entry was found.
                     */
                    const bool & found_entry() const
                    {
                        return m_found_entry;
                    }
                
                private:
                
                    /**
                     * The needle.
                     */
                    std::string m_needle;
                
                    /**
                     * If true the entry was deleted.
                     */
                    bool m_deleted;
                
                    /**
                     * The value.
                     */
                    std::string m_value;
                
                    /**
                     * If true the entry was found.
                     */
                    bool m_found_entry;
                
                protected:
                
                    // ...
            };
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * Constructor
             * @param file_mode The file mode.
             */
            db_tx(const std::string & file_mode = "r+");
        
            /**
             * Destructor
             */
            ~db_tx();
        
            /**
             * txn_begin
             */
            bool txn_begin();
        
            /**
             * txn_commit
             */
            bool txn_commit();
        
            /**
             * txn_abort
             */
            bool txn_abort();
    
            /**
             * Closes the database including the shared global state.
             */
            void close();
        
            /**
             * Loads the block index.
             * @param impl The stack_impl.
             */
            bool load_block_index(stack_impl & impl);
        
            /**
             * Checks if the transaction is in the database.
             * @param hash The sha256.
             */
            bool contains_transaction(const sha256 & hash);

            /**
             * Reads the database version.
             */
            bool read_version();
        
            /**
             * Writes the database version.
             */
            bool write_version();

            /**
             * Reads a transaction from disk.
             * @param hash The sha256.
             * @param tx The transaction.
             * @param index The transaction_index.
             */
            bool read_disk_transaction(
                const sha256 & hash, transaction & tx, transaction_index & index
            );
        
            /**
             * Reads a transaction from disk.
             * @param hash The sha256.
             * @param tx The transaction.
             */
            bool read_disk_transaction(const sha256 & hash, transaction & tx);
        
            /**
             * Reads a transaction from disk.
             * @param out_point The point_out.
             * @param tx The transaction.
             * @param index The transaction_index.
             */
            bool read_disk_transaction(
                const point_out & out_point, transaction & tx,
                transaction_index & index
            );
        
            /**
             * Reads a transaction from disk.
             * @param out_point The point_out.
             * @param tx The transaction.
             */
            bool read_disk_transaction(
                const point_out & out_point, transaction & tx
            );
    
            /**
             * Reads a transaction_index.
             * @param hash The sha256 hash.
             * @param index The transaction_index.
             */
            bool read_transaction_index(
                const sha256 & hash, transaction_index & index
            );
        
            /**
             * Updates a transaction index.
             * @param hash The sha256 hash.
             * @param index The transaction_index.
             */
            bool update_transaction_index(
                const sha256 & hash, transaction_index & index
            );

            /**
             * Erases a transaction index.
             * @param tx The transaction.
             */
            bool erase_transaction_index(const transaction & tx) const;
        
            /**
             * Writes the hash of the best chain.
             * @param hash The sha256 hash.
             */
            bool write_hash_best_chain(const sha256 & hash);
        
            /**
             * Writes the best invalid trust.
             * @param bn The big_number.
             */
            bool write_best_invalid_trust(big_number & bn);
        
            /**
             * Writes a blockindex.
             * @param value The block_index_disk.
             */
            bool write_blockindex(block_index_disk value);
        
            /**
             * Closes (global) leveldb::DB.
             */
            static void leveldb_close();
        
            /**
             * The (global) leveldb::DB cache size.
             * @param val The value.
             */
            static void set_leveldb_cache_size(const std::size_t & val);
        
            /**
             * The (global) leveldb::DB cache size.
             */
            static const std::size_t & leveldb_cache_size();
        
        private:
        
            /**
             * Loads the block index guts.
             * @param impl The stack_impl.
             */
            bool load_block_index_guts(stack_impl & impl);
        
            /**
             * Read the hash of the best chain.
             * @param hash The sha256 hash.
             */
            bool read_best_hash_chain(sha256 & hash);
        
            /**
             * Reads the best invalid trust.
             * @param bn The big_number.
             */
            bool read_best_invalid_trust(big_number & bn);
        
            /**
             * The version.
             */
            std::uint32_t m_version;

            /**
             * The (global) leveldb::DB.
             */
            static leveldb::DB * g_leveldbDB;
        
            /**
             * The (global) leveldb::DB cache size.
             */
            static std::size_t g_leveldb_cache_size;

            /**
             * The level::DB.
             */
            leveldb::DB * m_leveldbDB;
        
            /**
             * The leveldb::WriteBatch.
             */
            leveldb::WriteBatch * m_leveldbWriteBatch;
        
            /**
             * The leveldb::Options.
             */
            leveldb::Options m_leveldbWriteOptions;
        
        protected:
        
            /**
             * Reads a string.
             * @param key The key.
             * @param val The value.
             */
            bool read_string(const std::string & key, std::string & val);
        
            /**
             * Writes a string.
             * @param key The key.
             * @param val The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write_string(
                const std::string & key, const std::string & val,
                const bool & overwrite = true
            );
        
            /**
             * reads a sha256 hash.
             * @param key The key.
             * @param value The value.
             */
            bool read_sha256(const std::string & key, sha256 & val);
        
            /**
             * Writes a sha256 hash.
             * @param key The data_buffer.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write_sha256(
                const std::string & key, const sha256 & val,
                const bool & overwrite = true
            );
        
            /**
             * Reads a big_number.
             * @param key The key.
             * @param value The big_number.
             */
            bool read_big_number(const std::string & key, big_number & value);

            /**
             * Reads a key/value pair.
             * @param key The data_buffer.
             * @param value The value.
             */
            template<typename T>
            bool read(const data_buffer & key, T & value);
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1, typename T2>
            bool write(
                const T1 & key, T2 & value, const bool & overwrite = true
            );
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1>
            bool write(
                const std::pair<std::string, sha256> & key, T1 & value,
                const bool & overwrite = true
            );
        
            /**
             * Checks if the key exists.
             * @param key The data_buffer.
             */
            bool exists(const data_buffer & key);
        
            /**
             * Checks if the key exists.
             * @param key The std::string.
             */
            bool exists(const std::string & key);
        
            /**
             * Erase the given key.
             * @param key The data_buffer.
             */
            bool erase(const data_buffer & key) const;
        
            /**
             * Erase the given key.
             * @param key The std::pair.
             */
            bool erase(
                const std::pair<std::string, std::vector<std::uint8_t> > & key
                ) const
            ;
            
            /**
             * Scans
             * @param key The key.
             * @param value The value.
             * @param deleted If true the entry was deleted.
             */
            bool scan_batch(
                const data_buffer & key, std::string & value, bool & deleted
            ) const;
    };
#endif // USE_LEVELDB
    
} // namespace coin

#endif // COIN_DB_TX_LDB_HPP
