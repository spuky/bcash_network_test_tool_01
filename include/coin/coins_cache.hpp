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

#ifndef COIN_COINS_CACHE_HPP
#define COIN_COINS_CACHE_HPP

#include <cassert>
#include <cstdint>
#include <map>
#include <mutex>
#include <limits>
#include <vector>

#include <boost/format.hpp>

#include <coin/block_index.hpp>
#include <coin/coin_output.hpp>
#include <coin/coins.hpp>
#include <coin/coins_database.hpp>
#include <coin/logger.hpp>
#include <coin/sha256.hpp>
#include <coin/utility.hpp>

namespace coin {

	/**
	 * Implements a cache of unspent transaction outputs (UTXO's).
     */
	class coins_cache
    {
    	public:
     
			/**
			 * The minimum cached coins to keep (in-memory).
    		 * @note Should be configurable.
			 */
            enum { minimum = 65535 };
    
			/**
   			 * Constructor
       		 */
        	coins_cache()
         		: m_block_index_best(nullptr)
         	{
          		// ...
          	}
        
            /**
             * The singleton accessor.
             */
            static coins_cache & instance()
            {
                static coins_cache g_coins_cache;
                
                return g_coins_cache;
            }
        
        	/**
         	 * Opens
           	 */
            bool open(const std::size_t & cache_size)
            {
                /**
                 * Get the database path.
                 */
                auto path_database = filesystem::data_path() + "utxos/";
                
            	auto ret = coins_database::instance().open(
             	   path_database, cache_size
                );

                log_info(
                    "Coins cache is restoring reorganize datas from disk."
                );
                
				auto path_reorg =
    	            filesystem::data_path() + "blockchain/peer/reorg/"
                ;
                
                filesystem::create_path(path_reorg);
                
                auto contents = filesystem::path_contents(path_reorg);
                
                auto count = 0;
                
                for (auto & i : contents)
                {
                	/**
                	 * Skip filenames that start with '.'.
                  	 */
                	if (i[0] == '.')
                 	{
                  		continue;
                  	}
                    
                    auto f = std::make_shared<file>();
                    
                    if (f->open((path_reorg + i).c_str(), "rb"))
                    {
                        if (f->seek_set(0) != 0)
                        {
                            // :TODO: log_error
                        }
                        else
                        {
                            data_buffer buffer;
                        
                        	buffer.resize(f->size());
                        	
                        	f->read(buffer.data(), buffer.size());

							f->close();
                            
                            while (
                            	buffer.remaining() >=
                                sizeof(coins::reorganize_data_t)
                                )
                            {
                            	coins::reorganize_data_t coins_reorganize_data;
                            
                            	try
                             	{
                            		coins_reorganize_data.decode(buffer);
                              	}
                               	catch (...)
                                {
                                	break;
                                }
                             
                             	set_reorganize_datas(
                                	coins_reorganize_data.height,
                                    coins_reorganize_data, false
                                );
                            }
                            
                            count++;
                        }
                    }
                    else
                    {
                        // :TODO: log_error
                    }
                }
                
                log_info(
                    "Coins cache restored " << count <<
                    " reorganize datas from disk."
                );
             
            	return ret;
            }
        
            /**
			 * Closes
			 */
            bool close()
            {
            	auto ret = coins_database::instance().close();
             
             	m_coins_map.clear();
              
              	m_block_index_best = nullptr;
               
               return ret;
            }
        
           	/**
             * Gets coins.
             * @param txid The transaction identifier.
             * @param coins_out The coins (out).
             */
         	bool get_coins(const sha256 & txid, coins & coins_out)
          	{
           		std::lock_guard<std::mutex> l1(mutex_);
                
           		if (m_coins_map.count(txid) > 0)
             	{
              		coins_out = m_coins_map[txid];
                
                	return true;
              	}

                 /**
                  * Coins not found in memory cache; fall back to on-disk
                  * database.
                  */
                 if (
                    coins_database::instance().get_coins(
                    txid, coins_out) == true
                    )
                 {
                 	m_coins_map[txid] = coins_out;
                 	
                    return true;
                }

				return false;
           	}
        
        	/**
         	 * Gets coins.
           	 * @param txid The transaction identifier.
           	 */
            coins & get_coins(const sha256 & txid)
            {
            	auto it = fetch_coins(txid);
             
             	std::lock_guard<std::mutex> l1(mutex_);
                
             	if (it == m_coins_map.end())
              	{
               		log_error(
                       "Coins cache failed to get coins for " <<
                       txid.to_string() << ", not found."
                   );
               	}
                
             	assert(it != m_coins_map.end());
              
              	return it->second;
            }
        
            /**
             * Gets coins given txid and returns false if we do not have them.
             * @param txid The transaction identifier.
             * @param coins_out The coins_out (out).
             */
            bool get_if_have_coins(const sha256 & txid, coins & coins_out)
            {
                auto it = fetch_coins(txid);
             
                std::lock_guard<std::mutex> l1(mutex_);
                
                if (it != m_coins_map.end())
                {
					coins_out = it->second;
                 
					return true;
                }
                
                return false;
            }
        
			/**
             * Sets coins.
             * @param txid The transaction identifier.
             * @param coins_in The coins (in).
             */
            bool set_coins(const sha256 & txid, const coins & coins_in)
            {
            	std::lock_guard<std::mutex> l1(mutex_);
                
                m_coins_map[txid] = coins_in;
                
            	return coins_database::instance().set_coins(txid, coins_in);
            }
        
            /**
             * If true we have the coins given transaction identifier.
             * @param txid The transaction identifier.
             */
            bool have_coins(const sha256 & txid)
            {
                auto it = fetch_coins(txid);
                
                std::lock_guard<std::mutex> l1(mutex_);
                
            	return it != m_coins_map.end();
            }
        
            /**
             * Performs a batch write operation.
             * @param coins_map The std::map<sha256, coins>.
             * @param index The block_index.
             */
            bool batch_write(
            	const std::map<sha256, coins> & coins_map,
                const block_index * index
                )
            {
            	std::lock_guard<std::mutex> l1(mutex_);
                
            	for (auto & i : coins_map)
             	{
              		m_coins_map[i.first] = i.second;
              	}
                
				m_block_index_best = const_cast<block_index *> (index);
            
            	return true;
            }
        
            /**
             * Flushes the cache if writing to on-disk database was a success.
             * @param clear If true clear the in-memory cache.
             */
             bool flush(const bool & clear)
             {
             	auto ret = true;

				std::lock_guard<std::mutex> l1(mutex_);

				/**
    			 * Batch write to on-disk database.
                 */
             	ret = coins_database::instance().batch_write(
                	m_coins_recent_spends_map, m_block_index_best
				);

    			if (clear == true && ret == true)
       			{
                    /**
                     * Try to maintain a 75% full cache during initial block
                     * download.
                     */
					if (utility::is_initial_block_download() == false)
     				{
          				m_coins_map.clear();
					}
     				else
         			{
                        auto it = m_coins_map.begin();

                        std::advance(it, m_coins_map.size() / 4);
                        
                        m_coins_map.erase(m_coins_map.begin(), it);
					}
          		}
            
                static auto g_counter = 0;
    
                if (++g_counter % 8 == 0)
				{
					log_info(
						"Coins cache flush, cache size = " <<
						m_coins_map.size() << ", flushed = " <<
                        m_coins_recent_spends_map.size() << "."
					);
				}
    
    			m_coins_recent_spends_map.clear();

             	return ret;
             }
        
            /**
             * The size of the coins map.
             */
			const std::size_t size() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
             
				return m_coins_map.size();
            }
        
            /**
             * Sets the best block_index.
             * @param val The block_index.
             */
            bool set_block_index_best(const block_index * val)
            {
 				/**
     			 * Set the best block_index in the on-disk database.
                 */
				coins_database::instance().set_block_index_best(val);
                
                m_block_index_best = const_cast<block_index *> (val);
             
             	return true;
            }
        
            /**
			 * The best block_index.
			 */
         	block_index * block_index_best()
            {
				/**
				 * Block index not found in memory cache; fall back to on-disk
				 * database.
				 */
                if (m_block_index_best == nullptr)
                {
					m_block_index_best =
                       const_cast<block_index *> (coins_database::instance(
                       ).block_index_best())
                    ;
				}

            	return m_block_index_best;
            }
        
        	/**
        	 * Sets the coins::reorganize_data_t for the given height.
          	 * @param height The block height.
             * @param coins_reorganize_data The coins::reorganize_data_t.
             */
            void set_reorganize_datas(
            	const std::uint32_t & height,
                const coins::reorganize_data_t & coins_reorganize_data,
                const bool & write_to_disk = true
                )
            {
				std::lock_guard<std::mutex> l1(mutex_);
                
            	auto it = m_reorganize_datas.begin();
             
             	while (it != m_reorganize_datas.end())
              	{
               		/**
                  	 * The maximum block reorganization that can occur without
                     * causing a spend mismatch (corruption) in the
                     * coins_database.
                     */
               		enum { maximum_reorganization = 220 };
                    
               		if (
						m_block_index_best &&
                        m_block_index_best->height() > maximum_reorganization &&
                        it->first < m_block_index_best->height() -
                        maximum_reorganization
						)
                 	{
                  		std::stringstream ss;
                        
                  		std::string path_reorg = "blockchain/peer/reorg/";
                        
                        ss <<
                            filesystem::data_path() << path_reorg <<
                            boost::format("blk%llu.dat") % it->first
                        ;
                
                  		file::remove(ss.str());
                        
                  		it = m_reorganize_datas.erase(it);
                  	}
                   	else
                    {
                    	++it;
                    }
               	}
            	
                m_reorganize_datas[height].push_back(coins_reorganize_data);

				if (write_to_disk == true)
    			{
                    std::stringstream ss;
                
                    std::string path_reorg = "blockchain/peer/reorg/";
                
                    ss <<
                        filesystem::data_path() << path_reorg <<
                        boost::format("blk%llu.dat") % height
                    ;

                    auto ret = std::make_shared<file>();
                    
                    if (ret->open(ss.str().c_str(), "ab"))
                    {
                        if (ret->seek_end() != true)
                        {
                            // :TODO: log_error
                        }
                        else
                        {
                            data_buffer buffer;
                        
                            coins_reorganize_data.encode(buffer);
                        
                            ret->write(buffer.data(), buffer.size());
          
                            ret->close();
                        }
                    }
                    else
                    {
                        // :TODO: log_error
                    }
                }
            }
        
        	/**
         	 * Gets coins::reorganize_data_t objects given height.
             * @param height The height.
             * @param coins_reorganize_data The coins::reorganize_data_t's
             * (out).
             */
            bool get_reorganize_datas(
                const std::uint32_t & height,
                std::vector<coins::reorganize_data_t> & coins_reorganize_data
            	)
            {
            	std::lock_guard<std::mutex> l1(mutex_);
                
            	auto it = m_reorganize_datas.find(height);
             
             	if (it != m_reorganize_datas.end())
              	{
             		coins_reorganize_data = it->second;
               
               		return true;
              	}
             
             	return false;
            }

            /**
             *  The coins (recent spends) map.
             */
            std::map<sha256, coins> & coins_recent_spends_map()
            {
            	return m_coins_recent_spends_map;
            }
        
     	private:
      
      		/**
   		     *  The coins map.
        	 */
			std::map<sha256, coins> m_coins_map;
        
        	/**
         	 * The best block_index.
           	 */
         	block_index * m_block_index_best;
        
        	/**
          	 * The coins::reorganize_data_t objects for each block height.
             * @note The size of this map can be configured to limit the
             * maximum block reorganization depth.
             */
          	std::map<
				std::uint32_t, std::vector<coins::reorganize_data_t>
			> m_reorganize_datas;

			/**
             *  The coins (recent spends) map.
			 */
            std::map<sha256, coins> m_coins_recent_spends_map;
        
      	protected:
       
            /**
             * The std::mutex.
             */
            mutable std::mutex mutex_;
        
			/**
   			 * Fetches coins.
       		 */
    		std::map<sha256, coins>::iterator fetch_coins(const sha256 & txid)
      		{
        		std::lock_guard<std::mutex> l1(mutex_);

				auto it = m_coins_map.lower_bound(txid);
          
                if (it != m_coins_map.end() && it->first == txid)
                {
					return it;
                }
              
                /**
                 * Coins not found in memory cache; fall back to on-disk
                 * database.
                 */
                coins coins_db;
                
                 if (
                    coins_database::instance().get_coins(
                    txid, coins_db) == false
                    )
				{
                    return m_coins_map.end();
				}
    
    			auto ret = m_coins_map.insert(
                	it, std::make_pair(txid, coins())
                );
                
    			coins_db.swap(ret->second);

				return ret;
        	}
    };
    
} // namespace coin

#endif //  COIN_COINS_CACHE_HPP
