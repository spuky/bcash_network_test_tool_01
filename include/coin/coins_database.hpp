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

#ifndef COIN_COINS_DATABASE_HPP
#define COIN_COINS_DATABASE_HPP

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <coin/block_index.hpp>
#include <coin/coins.hpp>
#include <coin/db_tx.hpp> /* Header only used for USE_LEVELDB inclusion. */
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/sha256.hpp>

#if (defined USE_LEVELDB && USE_LEVELDB)
#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <leveldb/write_batch.h>
#endif // USE_LEVELDB

namespace coin {

    /**
     * Implements a database of unspent transaction outputs (UTXO's).
     */
	class coins_database
	{
        public:
        
#if (defined USE_LEVELDB && USE_LEVELDB)
            /**
             * Implements a leveldb::WriteBatch wrapper.
             */
			class leveldbWriteBatch
   			{
      			public:
            
					/**
					 * The leveldb::WriteBatch.
					 */
                 	leveldb::WriteBatch & get()
                    {
                    	return m_leveldbWriteBatch;
                    }
              
                    /**
                     * Writes
                     */
                    template<typename T1, typename T2>
                    void write(const T1 & key, T2 & value)
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
                            value_data.data(),
                            value_data.data() + value_data.size()
                        );
                        
                        m_leveldbWriteBatch.Put(key_str, value_str);
                    }

					/**
     				 * Writes
          			 */
                    template<typename T1>
                    void write(
                        const std::pair<std::string, sha256> & key, T1 & value
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
                            value_data.data(),
                            value_data.data() + value_data.size()
                        );
                        
                        m_leveldbWriteBatch.Put(key_str, value_str);
                    }
                
					/**
                     * Erases
                     */
                    void erase(
                        const std::pair<std::string, sha256> & key
                        ) const
                    {
                        data_buffer buffer;

                        buffer.write_var_int(key.first.size());
                        buffer.write_bytes(key.first.data(), key.first.size());
                        
                        buffer.write_sha256(key.second);

						std::string key_to_delete(
							buffer.data(), buffer.data() + buffer.size()
                        );

						m_leveldbWriteBatch.Delete(key_to_delete);
                    }
                
         		private:
           
           			/**
              		 * The leveldb::WriteBatch.
                 	 */
					mutable leveldb::WriteBatch m_leveldbWriteBatch;
                
           		protected:
             
             		// ...
      		};
#endif // USE_LEVELDB
            /**
			 * Constructor
			 */
            coins_database()
#if (defined USE_LEVELDB && USE_LEVELDB)
            	: m_leveldbEnv(nullptr)
             	, m_leveldbDB(nullptr)
#endif // USE_LEVELDB
			{
				// ...
			}
        
            /**
             * The singleton accessor.
             */
            static coins_database & instance()
            {
                static coins_database g_coins_database;
                
                return g_coins_database;
            }
        
#if (defined USE_LEVELDB && USE_LEVELDB)
			/**
			 * The default cache size.
             */
         	enum { default_cache_size = 25 };

            /**
             * The leveldb::Options.
             */
            static leveldb::Options leveldbOptions(
            	const std::size_t & cache_size = default_cache_size
                )
            {
                leveldb::Options ret;
                
                ret.block_cache = leveldb::NewLRUCache(
                	(cache_size * 1024 * 1024) / 2
                );
                ret.write_buffer_size = (cache_size * 1024 * 1024) / 4;
                ret.filter_policy = leveldb::NewBloomFilterPolicy(10);
                ret.compression = leveldb::kNoCompression;
                ret.max_open_files = 64;
                
                return ret;
            }
#endif // USE_LEVELDB
        
            /**
			 * Opens
			 */
            bool open(
            	const std::string & path,
                const std::size_t & cache_size = default_cache_size
                )
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
                m_leveldbReadOptions.verify_checksums = true;
                m_leveldbReadOptions_iter.verify_checksums = true;
                m_leveldbReadOptions_iter.fill_cache = false;
                m_leveldbWriteOptions_sync.sync = true;
                m_leveldbOptions = leveldbOptions(cache_size);
                m_leveldbOptions.create_if_missing = true;
                
                filesystem::create_path(path);
                
                log_info(
                    "Coins database (leveldb) initializing, path = " <<
                    path << "."
                );
                
    			auto status = leveldb::DB::Open(
					m_leveldbOptions, path, &m_leveldbDB
                );
                
				if (status.ok() == false)
    			{
        			throw std::runtime_error(
						"coins_database: error opening database "
                        "environment " + status.ToString()
                    );
                    
                    return false;
                }
                
                log_info("Coins database opened LevelDB successfully.");
#endif // USE_LEVELDB
            	return true;
            }
        
            /**
             * Closes
             */
            bool close()
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
                delete m_leveldbDB, m_leveldbDB = nullptr;
                delete m_leveldbOptions.filter_policy,
                	m_leveldbOptions.filter_policy = nullptr
                ;
                delete m_leveldbOptions.block_cache,
                	m_leveldbOptions.block_cache = nullptr
                ;
                delete m_leveldbEnv, m_leveldbEnv = nullptr;
                m_leveldbOptions.env = nullptr;
#endif // USE_LEVELDB
         		return true;
            }
        
        	/**
             * Does nothing.
             */
        	bool flush()
         	{
          		// ...
            
            	return true;
          	}
        
        	/**
         	 * Performs a m_leveldbWriteOptions_sync.sync operation.
           	 */
            bool sync()
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
                leveldbWriteBatch batch;
                
                return write_batch(batch, true);
#else
				return true;
#endif
            }
        
            /**
             * Sets the best block_index.
             * @param val The block_index.
             */
            bool set_block_index_best(const block_index * val)
            {
            	if (val != nullptr)
             	{
#if (defined USE_LEVELDB && USE_LEVELDB)
				leveldbWriteBatch batch;
             
             	batch_write_hash_best_chain(batch, val->get_block_hash());
              
                return write_batch(batch);
#else
				return true;
#endif // USE_LEVELDB
				}
    			
       			return false;
            }
        
            /**
             * The best block_index.
             */
            const block_index * block_index_best()
            {
                sha256 hash_best_chain;

                if (read(std::string("B"), hash_best_chain) == false)
                {
                    return nullptr;
                }

                if (
                    globals::instance().block_indexes().count(
                    hash_best_chain) == 0
                    )
                {
                    return nullptr;
                }

         		return globals::instance().block_indexes()[hash_best_chain];
            }
        
     		/**
             * Gets coins.
             * @param txid The transaction identifier.
             * @param coins_out The coins (out).
             */
			bool get_coins(const sha256 & txid, coins & coins_out)
			{
				return read(std::make_pair(std::string("c"), txid), coins_out);
			}
			
            /**
             * Sets coins.
             * @param txid The transaction identifier.
             * @param coins_in The coins (in).
             */
            bool set_coins(const sha256 & txid, const coins & coins_in)
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
                leveldbWriteBatch batch;
                
                batch_write_coins(batch, txid, coins_in);
                
                return write_batch(batch);
#else
                return true;
#endif
            }

            /**
             * If true we have the coins given transaction identifier.
             * @param txid The transaction identifier.
             */
            bool have_coins(const sha256 & txid)
            {
                return exists(std::make_pair(std::string("c"), txid));
            }

			/**
    		 * Gets statistics.
             */
            bool get_stats(coins::statistics_t & coins_statistics)
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
				auto * ptr_cursor = m_leveldbDB->NewIterator(
    	            m_leveldbReadOptions_iter
                );
    
    			ptr_cursor->SeekToFirst();
       			
               	auto index = 0;
       			
             	while (ptr_cursor->Valid() == true)
          		{
            		try
              		{
                        auto key = ptr_cursor->key();
                        
                        data_buffer buffer_key(key.data(), key.size());
                        
                        auto prefix = buffer_key.read_bytes(
                        	buffer_key.read_var_int()
                        );
                
                        if (prefix[0] == 'c')
                        {
                        	index++;
        
                        	auto hash_tx = buffer_key.read_sha256();
                         
                         	(void)hash_tx;
                            
                            auto value = ptr_cursor->value();
     
							data_buffer buffer_value(
                            	value.data(), value.size()
                            );
                            
                            coins coins_cached;
                            
                            coins_cached.decode(buffer_value);

							for (auto & i : coins_cached.transaction_outs())
       						{
             					if (i.is_null() == false)
                  				{
                      				coins_statistics.transaction_outputs++;
                      			}
             				}
                            
							coins_statistics.transactions++;
       
       						coins_statistics.encoded_size
								+= 32 + value.size()
							;
                        }
                        
                        ptr_cursor->Next();
                    }
                    catch (std::exception & e)
                    {
                    	log_error(
                     	   "Coins database failed to get_stats, what = " <<
                            e.what() << "."
                        );
                    }
            	}
       
       			delete ptr_cursor;
          
          		const auto & ptr_block_index_best = block_index_best();
                
                if (ptr_block_index_best != nullptr)
                {
          			coins_statistics.height = ptr_block_index_best->height();
                }
                
                log_info(
                	"Coins database statistics:\n" <<
                 	"\tHeight: " << coins_statistics.height << "\n" <<
					"\tTransactions: " << coins_statistics.transactions <<
                    "\n" <<
					"\tTransaction Outputs: " <<
                    coins_statistics.transaction_outputs << "\n" <<
					"\tEncoded Size: " << coins_statistics.encoded_size
                );
                
          		return true;
#else
				return true;
#endif // USE_LEVELDB
            }
        
            /**
             * Loads all coins from database into memory.
             */
            std::map<sha256, coins> load_coins()
            {
            	std::map<sha256, coins> ret;
#if (defined USE_LEVELDB && USE_LEVELDB)
                auto * ptr_cursor = m_leveldbDB->NewIterator(
                    m_leveldbReadOptions_iter
                );
    
                ptr_cursor->SeekToFirst();
                
                auto index = 0;
                
				while (ptr_cursor->Valid() == true)
				{
					try
					{
                        auto key = ptr_cursor->key();
                        
                        data_buffer buffer_key(key.data(), key.size());
                        
                        auto prefix = buffer_key.read_bytes(
                            buffer_key.read_var_int()
                        );
                
                        if (prefix[0] == 'c')
                        {
                            auto hash_tx = buffer_key.read_sha256();
    
                            auto value = ptr_cursor->value();
     
                            data_buffer buffer_value(
                                value.data(), value.size()
                            );
                            
                            coins coins_cached;
                            
                            coins_cached.decode(buffer_value);

							ret[hash_tx] = coins_cached;
                        }
                        
                        ptr_cursor->Next();
                    }
                    catch (std::exception & e)
                    {
                        log_error(
                            "Coins database failed to load_coins, what = " <<
                            e.what() << "."
                        );
                    }
                }
       
				delete ptr_cursor;
          
          		return ret;
#else
                return ret;
#endif // USE_LEVELDB
            }


            /**
             * Performs a batch write operation.
             * @param coins_map The std::map<sha256, coins>.
             * @param index The block_index.
             */
            bool batch_write(
             	std::map<sha256, coins> & coins_map,
                const block_index * index
                )
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
            	leveldbWriteBatch batch;
             	
              	log_debug(
					"Coins database queued " << coins_map.size() <<
                    " (possible) changed coins."
				);

                auto coins_changed = 0;

                for (auto & i : coins_map)
               	{
					batch_write_coins(batch, i.first, i.second);
                
					coins_changed++;
				}
             
				log_info(
					"Coins database wrote " << coins_changed <<
					" changed coins."
                );
        
				if (index)
                {
					batch_write_hash_best_chain(batch, index->get_block_hash());
     			}

				return write_batch(batch);
#else
				return true;
#endif // USE_LEVELDB
            }
        
            /**
             * Reads
             * @param key The key.
             * @param value The value.
             */
         	template<typename T1>
        	bool read(const data_buffer & key, T1 & value)
         	{
#if (defined USE_LEVELDB && USE_LEVELDB)
				std::string key_str(key.data(), key.data() + key.size());

                std::string value_str;

                auto status = m_leveldbDB->Get(
                    m_leveldbReadOptions, key_str, &value_str
                );
                
                if (status.ok() == false)
                {
                    if (status.IsNotFound() == true)
                    {
                        return false;
                    }

                    log_error(
                        "Coins database (leveldb) read failed, status = " <<
                        status.ToString() << "."
                    );
                
                    return false;
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
                        "Coins database (leveldb) read failed, what = " <<
                        e.what() << "."
                    );
                    
                    return false;
                }
#endif // USE_LEVELDB
                return true;
          	}
        
            /**
             * Reads
             * @param key The key.
             * @param value The value.
             */
            template<typename T1>
            bool read(const std::string & key, T1 & value)
			{
				data_buffer buffer;

                buffer.write_var_int(key.size());
                buffer.write_bytes(key.data(), key.size());
                
                return read(buffer, value);
            }
        
            /**
             * Reads
             * @param key The key.
             * @param value The value.
             */
            template<typename T1>
			bool read(const std::pair<std::string, sha256> & key, T1 & value)
   			{
                data_buffer buffer;

                buffer.write_var_int(key.first.size());
                buffer.write_bytes(key.first.data(), key.first.size());
                
                buffer.write_sha256(key.second);
                
                return read(buffer, value);
            }

            /**
             * Writes
             * @param key The key.
             * @param value The value.
             * @param synchronize If true the database will perform a
             * synchronized write.
             */
			template<typename T1, typename T2>
			bool write(
				const T1 & key, T2 & value, const bool & synchronize = false
            	)
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
				leveldbWriteBatch batch;
				
                batch.write(key, value);
				
                return write_batch(batch, synchronize);
#else
                return true;
#endif // USE_LEVELDB
            }
    
            /**
             * If true the given key exists.
             * @param key The key.
             */
        	bool exists(const std::pair<std::string, sha256> & key)
         	{
                data_buffer buffer;

                buffer.write_var_int(key.first.size());
                buffer.write_bytes(key.first.data(), key.first.size());
        
                buffer.write_sha256(key.second);

                std::string key_to_find(
                    buffer.data(), buffer.data() + buffer.size()
                );
                
                std::string value;

               	auto status = m_leveldbDB->Get(
					m_leveldbReadOptions, key_to_find, &value
				);
    
    			if (status.ok() == false)
       			{
          			if (status.IsNotFound() == true)
             		{
               			return false;
               		}
                 
					log_error(
						"Coins database (leveldb) exists (get) failed, "
						"status = " << status.ToString() << "."
					);
          		}
          
          		return true;
          	}
        
            /**
             * Erases the given key.
             * @param key The key.
             * @param synchronize If true the database will perform a
             * synchronized erase.
             */
            bool erase(
            	const std::pair<std::string, sha256> & key,
                const bool & synchronize = false
                )
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
                leveldbWriteBatch batch;
                
                batch.erase(key);
                
                return write_batch(batch, synchronize);
#else
                return true;
#endif // USE_LEVELDB
            }
    
        	/**
      		 * Performs a batch write operation.
         	 * @param batch The leveldbWriteBatch.
           	 * @param synchronize If true the database will perform a
             * synchronized write.
         	 */
            bool write_batch(
            	leveldbWriteBatch & batch, const bool & synchronize = false
                )
            {
#if (defined USE_LEVELDB && USE_LEVELDB)
				auto status = m_leveldbDB->Write(
    	            synchronize ? m_leveldbWriteOptions_sync :
                    m_leveldbWriteOptions, &batch.get()
                );
                
                if (status.ok() == false)
                {
                    log_error(
                        "Coins database (leveldb) write batch failed, "
                        "status = " << status.ToString() << "."
                    );
                    
                    return false;
                }
#endif // USE_LEVELDB
                return true;
            }
        
        private:
        
#if (defined USE_LEVELDB && USE_LEVELDB)
            /**
             * The leveldb::Env.
             */
            leveldb::Env * m_leveldbEnv;

			/**
   			 * The leveldb::Options.
       		 */
            leveldb::Options m_leveldbOptions;

			/**
   			 * The leveldb::ReadOptions (reading).
       		 */
            leveldb::ReadOptions m_leveldbReadOptions;

            /**
             * The leveldb::ReadOptions (iterating).
             */
            leveldb::ReadOptions m_leveldbReadOptions_iter;

            /**
             * The leveldb::WriteOptions (writing).
			 */
            leveldb::WriteOptions m_leveldbWriteOptions;
        
            /**
             * The leveldb::WriteOptions (sync).
             */
            leveldb::WriteOptions m_leveldbWriteOptions_sync;

			/**
   			 * The leveldb::DB.
       		 */
            leveldb::DB * m_leveldbDB;
#endif // USE_LEVELDB

        protected:

#if (defined USE_LEVELDB && USE_LEVELDB)
            /**
             * Performs a batch write of coins.
             * @param batch The leveldbWriteBatch.
             * @param hash_in The hash[in].
             * @param coins_in The coins[in].
             */
            void static batch_write_coins(
            	leveldbWriteBatch & batch, const sha256 & hash_in,
                const coins & coins_in
				)
            {
                if (coins_in.is_pruned() == true)
                {
                    batch.erase(std::make_pair(std::string("c"), hash_in));
                }
                else
                {
                    batch.write(
                    	std::make_pair(std::string("c"), hash_in), coins_in
                    );
                }
            }

			/**
             * Performs a batch write of the hash of the best chain.
             * @param batch The leveldbWriteBatch.
             * @param hash_in The hash[in].
             */
            void static batch_write_hash_best_chain(
            	leveldbWriteBatch & batch, const sha256 & hash_in
				)
            {
                batch.write(std::string("B"), hash_in);
            }
#endif // USE_LEVELDB
	};

} // namespace coin

#endif // COIN_COINS_DATABASE_HPP
