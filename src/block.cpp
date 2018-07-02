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

#include <algorithm>
#include <cassert>
#include <chrono>
#include <set>
#include <sstream>

#include <boost/format.hpp>

#include <coin/big_number.hpp>
#include <coin/block.hpp>
#include <coin/block_orphan.hpp>
#include <coin/block_index.hpp>
#include <coin/block_index_disk.hpp>
#include <coin/block_locator.hpp>
#include <coin/coins_cache.hpp>
#include <coin/constants.hpp>
#include <coin/db_tx.hpp>
#include <coin/file.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/key_reserved.hpp>
#include <coin/key_store.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/point_out.hpp>
#include <coin/reward.hpp>
#include <coin/script_checker_queue.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/time.hpp>
#include <coin/transaction_in.hpp>
#include <coin/transaction_out.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/utility.hpp>
#include <coin/version_bits.hpp>
#include <coin/wallet_manager.hpp>

using namespace coin;

block::block()
    : data_buffer()
{
    set_null();
}

void block::encode(const bool & block_header_only)
{
    encode(*this, block_header_only);
}

void block::encode(data_buffer & buffer, const bool & block_header_only)
{
    buffer.write_uint32(m_header.version);
    buffer.write_sha256(m_header.hash_previous_block);
    buffer.write_sha256(m_header.hash_merkle_root);
    buffer.write_uint32(m_header.timestamp);
    buffer.write_uint32(m_header.bits);
    buffer.write_uint32(m_header.nonce);
    
    /**
     * Connect block depends on the transactions following the header to
     * generate the transaction position.
     */
    if (block_header_only)
    {
        buffer.write_var_int(0);
    }
    else
    {
        buffer.write_var_int(m_transactions.size());
        
        for (auto & i : m_transactions)
        {
            i.encode(buffer);
        }
    }
}

bool block::decode(const bool & block_header_only)
{
    return decode(*this, block_header_only);
}

bool block::decode(data_buffer & buffer, const bool & block_header_only)
{
    m_header.version = buffer.read_uint32();
    m_header.hash_previous_block = buffer.read_sha256();
    m_header.hash_merkle_root = buffer.read_sha256();
    m_header.timestamp = buffer.read_uint32();
    m_header.bits = buffer.read_uint32();
    m_header.nonce = buffer.read_uint32();

    log_none(
        "version = " << m_header.version << ", timestamp = " <<
        m_header.timestamp << ", bits = " << m_header.bits <<
        ", nonce = " << m_header.nonce
    );
    
    assert(buffer.size());
    
    if (block_header_only)
    {
        buffer.read_var_int();
    }
    else
    {
        /**
         * Read the number of transactions.
         */
        auto number_transactions = buffer.read_var_int();
        
        /**
         * Decode the transactions.
         */
        for (auto i = 0; i < number_transactions; i++)
        {
            /**
             * Allocate the transaction.
             */
            transaction tx;
            
            /**
             * Decode the transaction.
             */
            tx.decode(buffer);
            
            /**
             * Retain the transaction.
             */
            m_transactions.push_back(tx);
        }
    }
    
    return true;
}

void block::set_null()
{
    m_header.version = current_version;
    m_header.hash_previous_block.clear();
    m_header.hash_merkle_root.clear();
    m_header.nonce = 0;
    m_header.bits = 0;
    m_header.nonce = 0;
    m_transactions.clear();
    m_signature.clear();
    m_merkle_tree.clear();
    m_peer_headers_first_sync_height = 0;
}

bool block::is_null() const
{
    return m_header.bits == 0;
}

sha256 block::get_hash() const
{
    sha256 ret;
    
    std::uint32_t * ptr = reinterpret_cast<std::uint32_t *>(ret.digest());
    
    data_buffer buffer;
    
    buffer.write_uint32(m_header.version);
    buffer.write_sha256(m_header.hash_previous_block);
    buffer.write_sha256(m_header.hash_merkle_root);
    buffer.write_uint32(m_header.timestamp);
    buffer.write_uint32(m_header.bits);
    buffer.write_uint32(m_header.nonce);

    assert(buffer.size() == header_length);

    auto digest = hash::sha256d(
        reinterpret_cast<std::uint8_t *>(buffer.data()), header_length
    );

    std::memcpy(ptr, &digest[0], digest.size());
    
    return ret;
}

const sha256 & block::get_tranaction_hash(const std::uint32_t & index) const
{
	assert(m_merkle_tree.size() > 0);
    
	assert(index < m_transactions.size());
    
	return m_merkle_tree[index];
}

sha256 block::get_hash_genesis()
{
    static const sha256 ret(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );

    return ret;
}

sha256 block::get_hash_genesis_test_net()
{
    static const sha256 ret(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    );

    return ret;
}

block::header_t & block::header()
{
    return m_header;
}

const block::header_t & block::header() const
{
    return m_header;
}

std::vector<transaction> & block::transactions()
{
    return m_transactions;
}

std::vector<std::uint8_t> & block::signature()
{
    return m_signature;
}

void block::update_time(block_index & previous)
{
    m_header.timestamp = std::max(
        m_header.timestamp,
        static_cast<std::uint32_t> (time::instance().get_adjusted())
    );
}

block block::create_genesis()
{
    /**
     * Genesis block creation.
     */
    std::string timestamp_quote =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    ;
    
    /**
     * Allocate a new transaction.
     */
    transaction tx_new;
    
    /**
     * Allocate one input.
     */
    tx_new.transactions_in().resize(1);
    
    /**
     * Allocate one output.
     */
    tx_new.transactions_out().resize(1);

    /**
     * Create the script signature.
     */
    auto script_signature =
        script() << 486604799 << big_number(4) <<
        std::vector<std::uint8_t>(
        (const std::uint8_t *)timestamp_quote.c_str(),
        (const std::uint8_t *)timestamp_quote.c_str() +
        timestamp_quote.size()
    );

    log_debug("script_signature = " << script_signature.to_string());
    
    /**
     * Set the script signature on the input.
     */
    tx_new.transactions_in()[0].set_script_signature(
        script_signature
    );
    
    /**
     * Set the script public key.
     */
    tx_new.transactions_out()[0].script_public_key() = script() << utility::from_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a679"
        "62e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702"
        "b6bf11d5f") << script::op_checksig
    ;
    
    /**
     * Set the output to (50 * constants::coin).
     */
    tx_new.transactions_out()[0].set_value(50 * constants::coin);
    
    /**
     * Allocate the genesis block.
     */
    block blk;
    
    /**
     * Add the transactions.
     */
    blk.transactions().push_back(tx_new);
    
    /**
     * There is no previous block.
     */
    blk.header().hash_previous_block = 0;
    
    /**
     * Build the merkle tree.
     */
    blk.header().hash_merkle_root = blk.build_merkle_tree();
    
    /**
     * Set the header version.
     */
    blk.header().version = 1;
    
    /**
     * Set the header timestamp.
     */
    if (constants::test_net == true)
    {
        blk.header().timestamp = 1296688602;
    }
    else
    {
        blk.header().timestamp = constants::chain_start_time;
    }
    
    log_debug(
        "Block header bits = " << constants::proof_of_work_limit.get_compact()
    );
    
    /**
     * Set the header bits.
     */
    blk.header().bits = 
        constants::proof_of_work_limit.get_compact()
    ;
    
    assert(blk.header().bits == 486604799);
    
    /**
     * The test network uses a different genesis block by using a
     * different nonce.
     */
    if (constants::test_net == true)
    {
        /**
         * Set the header nonce.
         */
        blk.header().nonce = 414098458;
    }
    else
    {
        /**
         * Set the header nonce.
         */
        blk.header().nonce = 2083236893;
    }

    /**
     * Print the block.
     */
    blk.print();
    
    data_buffer buf;
    
    blk.encode(buf);
    
    log_debug(utility::hex_string(buf.data(), buf.data() + buf.size()));

    log_debug(
        "Block hash = " << blk.get_hash().to_string() << "."
    );
    log_debug(
        "Block header hash merkle root = " <<
        blk.header().hash_merkle_root.to_string() << "."
    );
    log_debug(
        "Block header time = " << blk.header().timestamp << "."
    );
    log_debug(
        "Block header nonce = " << blk.header().nonce << "."
    );

    /**
     * Check the merkle root hash.
     */
    assert(
        blk.header().hash_merkle_root ==
        sha256("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7"
        "afdeda33b")
        
    );
    
    /**
     * Check the genesis block hash.
     */
    assert(
        blk.get_hash() ==
        (constants::test_net ? block::get_hash_genesis_test_net() :
        block::get_hash_genesis())
    );
    
    return blk;
}

std::shared_ptr<block> block::create_new(const std::shared_ptr<wallet> & w)
{
    static std::mutex g_mutex;
    
    std::lock_guard<std::mutex> l1(g_mutex);
    
    /**
     * Allocate a block.
     */
    auto ret = std::make_shared<block> ();
    
    /**
     * Allocate a key_reserved.
     */
    key_reserved reserved_key(*w);
    
    /**
     * Allocate a new (coinbase) transaction.
     */
    transaction tx_new;
    
    tx_new.transactions_in().resize(1);
    tx_new.transactions_in()[0].previous_out().set_null();
    tx_new.transactions_out().resize(1);
    tx_new.transactions_out()[0].script_public_key() <<
        reserved_key.get_reserved_key() << script::op_checksig
    ;
    
    /**
     * Add our (coinbase) transaction as the first transaction.
     */
    ret->transactions().push_back(tx_new);

    /**
     * Calculate the largest block we're willing to create.
     * -blockmaxsize
    */
    std::size_t max_size = get_maximum_size() / 4;
    
    /**
     * Limit to betweeen 1000 and block::get_maximum_size()
     * - 1000 for sanity.
     */
    max_size = std::max(
        static_cast<std::size_t> (1000),
        std::min((block::get_maximum_size() - 1000), max_size)
    );

    /**
     * How much of the block should be dedicated to high-priority transactions,
     * included regardless of the fees they pay.
     * -blockprioritysize
     */
    std::size_t priority_size = 27000;
    
    priority_size = std::min(max_size, static_cast<std::size_t> (priority_size));

    /**
     * Minimum block size you want to create; block will be filled with free
     * transactions until there are no more or the block reaches this size:
     * -blockminsize
     */
    std::size_t min_size = 0;
    
    min_size = std::min(max_size, static_cast<std::size_t> (min_size));
    
    /**
     * -mintxfee
     */
    std::int64_t min_transaction_fee = globals::instance().transaction_fee();

    /**
     * Collect transactions pool entries into a block.
     */
    
    std::int64_t fees = 0;

    auto index_previous = stack_impl::get_block_index_best();
    
    db_tx tx_db("r");

    /**
     * The priority of order in which to process transactions.
     */
    std::list< std::shared_ptr<block_orphan> > orphans;
    
    std::map<
        sha256, std::vector< std::shared_ptr<block_orphan> >
    > dependencies;

    std::vector< std::tuple<double, double, transaction *> > priorities;
    
    priorities.reserve(transaction_pool::instance().size());

    /**
     * Get the transaction_pool transactions.
     */
    auto transactions = transaction_pool::instance().transactions();
    
    for (auto it = transactions.begin(); it != transactions.end(); ++it)
    {
        auto & tx = it->second;
        
        if (tx.is_coin_base() || tx.is_final() == false)
        {
            continue;
        }
        
        std::shared_ptr<block_orphan> ptr_orphan;
        
        double priority = 0;
        
        std::int64_t total_in = 0;
        
        auto is_missing_inputs = false;
        
        for (auto & tx_in : tx.transactions_in())
        {
            transaction tx_previous;
            
            transaction_index tx_index;
            
            if (
                tx_previous.read_from_disk(tx_db, tx_in.previous_out(),
                tx_index) == false
                )
            {
                /**
                 * This should never be reached.
                 */
                if (transactions.count(tx_in.previous_out().get_hash()) == 0)
                {
                    log_error(
                        "Block, create new, transaction pool item is "
                        "missing input."
                    );

                    is_missing_inputs = true;
                    
                    if (ptr_orphan)
                    {
                        orphans.pop_back();
                    }
                    
                    break;
                }

                if (ptr_orphan == 0)
                {
                    orphans.push_back(std::make_shared<block_orphan> (tx));
                    
                    ptr_orphan = orphans.back();
                }
                
                dependencies[tx_in.previous_out().get_hash()].push_back(
                    ptr_orphan
                );
                
                ptr_orphan->dependencies().insert(
                    tx_in.previous_out().get_hash()
                );
                
                total_in += 
                    transactions[tx_in.previous_out().get_hash()
                    ].transactions_out()[tx_in.previous_out().n()].value()
                ;
                
                continue;
            }
            
            std::int64_t value_in = tx_previous.transactions_out()[
                tx_in.previous_out().n()
            ].value();
            
            total_in += value_in;

            auto conf = tx_index.get_depth_in_main_chain();
            
            priority += static_cast<double> (value_in) * conf;
        }
        
        if (is_missing_inputs)
        {
            continue;
        }
        
        /**
         * priority = sum(value * age) / transaction size
         */
        
        data_buffer buffer;
        
        tx.encode(buffer);
    
        auto tx_size = buffer.size();
    
        priority /= tx_size;

        double fee_per_kilobyte =  double(
            total_in - tx.get_value_out()) / (double(tx_size) / 1000.0
        );

        if (ptr_orphan)
        {
            ptr_orphan->set_priority(priority);
            
            ptr_orphan->set_fee_per_kilobyte(fee_per_kilobyte);
        }
        else
        {
            priorities.push_back(
                std::make_tuple(priority, fee_per_kilobyte, &it->second)
            );
        }
    }

    /**
     * Collect the transactions into block.
     */
    
    std::map<sha256, transaction_index> test_pool;
    
    std::int64_t block_size = 1000;
    
    std::uint64_t block_tx = 0;
    
    auto block_sig_ops = 100;
    
    bool sorted_by_fee = (priority_size <= 0);

    transaction_fee_priority_compare comparer(sorted_by_fee);
    
    std::make_heap(priorities.begin(), priorities.end(), comparer);

    while (priorities.size() > 0)
    {
        double priority = std::get<0> (priorities.front());
        
        double fee_per_kilobyte = std::get<1> (priorities.front());
        
        transaction & tx = *std::get<2>(priorities.front());

        std::pop_heap(priorities.begin(), priorities.end(), comparer);
        
        priorities.pop_back();

        data_buffer buffer;
        
        tx.encode(buffer);
        
        auto tx_size = buffer.size();

        if (block_size + tx_size >= block::get_maximum_size())
        {
            continue;
        }
        
        auto sig_ops = tx.get_legacy_sig_op_count();
        
        if (block_sig_ops + sig_ops >= block::get_maximum_size() / 50)
        {
            continue;
        }
        
        if (tx.time() > time::instance().get_adjusted())
        {
            continue;
        }
        
        /**
         * Simplify transaction fee - allow free = false (ppcoin).
         */
        std::int64_t min_fee = tx.get_minimum_fee(
            static_cast<std::uint32_t> (block_size), false,
            types::get_minimum_fee_mode_block
        );

        if (
            sorted_by_fee && (fee_per_kilobyte < min_transaction_fee) &&
            (block_size + tx_size >= min_size)
            )
        {
            continue;
        }

        if (
            sorted_by_fee == false &&
            ((block_size + tx_size >= priority_size) ||
            (priority < constants::coin * 144 / 250))
            )
        {
            sorted_by_fee = true;
            
            comparer = transaction_fee_priority_compare(sorted_by_fee);
            
            std::make_heap(priorities.begin(), priorities.end(), comparer);
        }

        std::map<sha256, transaction_index> test_pool_copy(test_pool);
        
        std::map<sha256, std::pair<transaction_index, transaction> > inputs;
        
        bool invalid;
        
        if (
            tx.fetch_inputs(tx_db, test_pool_copy, false, true, inputs,
            invalid) == false
            )
        {
            continue;
        }
        
        std::int64_t transaction_fees =
            tx.get_value_in(inputs) - tx.get_value_out()
        ;
        
        if (transaction_fees < min_fee)
        {
            continue;
        }
        
        sig_ops += tx.get_p2sh_sig_op_count(inputs);

        if (block_sig_ops + sig_ops >= block::get_maximum_size() / 50)
        {
            continue;
        }
        
        if (
            tx.connect_inputs(tx_db, inputs, test_pool_copy,
            transaction_position(1, 1, 1), index_previous, false, true) == false
            )
        {
            continue;
        }

        test_pool_copy[tx.get_hash()] = transaction_index(
            transaction_position(1, 1, 1),
            static_cast<std::uint32_t> (tx.transactions_out().size())
        );
        
        std::swap(test_pool, test_pool_copy);

        ret->transactions().push_back(tx);
        
        block_size += tx_size;
        
        ++block_tx;
        
        block_sig_ops += sig_ops;
        
        fees += transaction_fees;

        /**
         * -printpriority;
         */
        if (globals::instance().debug() && false)
        {
            log_debug(
                "Block, create new, priority = " << priority <<
                ", fee_per_kilobyte = " << fee_per_kilobyte <<
                ", hash(tx id) = " << tx.get_hash().to_string() << "."
            );
        }

        /**
         * Add the transactions that depend on this one to the priority queue.
         */
        sha256 hash = tx.get_hash();
        
        if (dependencies.count(hash) > 0)
        {
            for (auto & i : dependencies[hash])
            {
                if (!i->dependencies().empty())
                {
                    i->dependencies().erase(hash);
                    
                    if (i->dependencies().empty())
                    {
                        priorities.push_back(
                            std::make_tuple(static_cast<double> (
                            i->priority()), static_cast<double> (
                            i->fee_per_kilobyte()),
                            const_cast<transaction *> (&i->get_transaction()))
                        );
                        
                        std::push_heap(
                            priorities.begin(), priorities.end(), comparer
                        );
                    }
                }
            }
        }
    }

    /**
     * Set the number of transactions in the last block transaction.
     */
    globals::instance().set_last_block_transactions(block_tx);
    
    /**
     * Set the last block size.
     */
    globals::instance().set_last_block_size(block_size);

    /**
     * -printpriority
     */
    if (globals::instance().debug())
    {
        log_debug("Block, create new total size = " << block_size << ".");
    }
    
    if (ret->is_proof_of_work() == true)
    {
        ret->transactions()[0].transactions_out()[0].set_value(
            reward::get_proof_of_work(index_previous->height() + 1, fees,
            index_previous->get_block_hash())
        );
    }
    
    /**
     * Compute and set the (BIP9) block version.
     */
    ret->header().version = version_bits::instance().block_version_compute(
        index_previous, version_bits::instance().parameters() 
    );
    
    /**
     * Fill in the block header.
     */
    ret->header().hash_previous_block = index_previous->get_block_hash();
    
    ret->header().timestamp = std::max(
        static_cast<std::uint32_t> (index_previous->get_median_time_past() + 1),
        static_cast<std::uint32_t> (ret->get_max_transaction_time())
    );
    
    ret->header().timestamp = std::max(
        static_cast<std::uint32_t> (ret->header().timestamp),
        static_cast<std::uint32_t> (index_previous->time() -
        constants::max_clock_drift)
    );
    
    if (ret->is_proof_of_work())
    {
        ret->update_time(*index_previous);
    }
    
    ret->header().nonce = 0;

    index_previous = stack_impl::get_block_index_best();

    ret->header().bits = utility::get_next_target_required(
        index_previous, ret.get()
    );
    
    return ret;
}

bool block::disconnect_block(db_tx & tx_db, block_index * index)
{
    /**
     * Disconnect in reverse order.
     */
    for (
        std::int32_t i = static_cast<int> (m_transactions.size()) - 1;
        i >= 0; i--
        )
    {
        if (m_transactions[i].disconnect_inputs(tx_db) == false)
        {
            return false;
        }
    }
    
    /**
     * Update block index on disk without changing it in memory. The memory
     * index structure will be changed after the database commits.
     */
    if (index->block_index_previous())
    {
        block_index_disk previous(*index->block_index_previous());

        /**
         * Set the next hash to null.
         */
        previous.set_hash_next(0);
        
        if (tx_db.write_blockindex(previous) == false)
        {
            log_error("Block, disconnect failed, write block index failed");
            
            return false;
        }
    }

    /**
     * Clean up wallet after disconnecting.
     */
    for (auto & i : m_transactions)
    {
        wallet_manager::instance().sync_with_wallets(i, this, false, false);
    }
    
    return true;
}

bool block::disconnect_block_2(db_tx & tx_db, block_index * index)
{
	auto ret = true;

	if (index != coins_cache::instance().block_index_best())
	{
		throw std::runtime_error(
			"block disconnect index does not match coins cache"
    	);
        
		return false;
	}
	
	/**
	 * @note Reorganize needs testing.
	 */

	/**
	 * Get the coins::reorganize_data_t objects for this block height.
     */
    std::vector<coins::reorganize_data_t> coins_reorganize_data;
    
    if (
		coins_cache::instance().get_reorganize_datas(index->height(),
		coins_reorganize_data) == true
		)
    {
    	std::uint32_t total_inputs = 0;
        
    	for (auto & i : m_transactions)
     	{
      		total_inputs += i.transactions_in().size();
      	}
        
        if (coins_reorganize_data.size() + 1 != total_inputs)
        {
        	log_error(
         	   "Block disconnect failed, reorganize data inconsistent (" <<
                coins_reorganize_data.size() << "/" << total_inputs << ")."
            );
            
            throw std::runtime_error(
                "block disconnect reorganize data inconsistent"
            );

            return false;
        }
    }
    else
    {
        throw std::runtime_error("block disconnect reorganize data missing");
    
        return false;
    }
	
    /**
     * Disconnect in reverse order.
     */
    for (
        std::int32_t i = static_cast<int> (m_transactions.size()) - 1;
        i >= 0; i--
        )
    {
        auto hash_tx = m_transactions[i].get_hash();

        /**
         * Check that we have the outputs.
         */
        if (coins_cache::instance().have_coins(hash_tx) == false)
        {
        	log_error(
         	   "Block disconnect, outputs must be still spent, possible "
                "coin database problem."
            );
            
            ret = ret && false;
            
            coins_cache::instance().set_coins(hash_tx, coins());
        }
        
     	auto & coins_out = coins_cache::instance().get_coins(hash_tx);

        auto coins_out_block = coins(m_transactions[i], index->height());
        
        if (coins_out != coins_out_block)
        {
            log_error(
            	"Block disconnect, set transaction mismatch, possible coin "
                "database problem."
            );
            
            ret = ret && false;
        }

        /**
         * Clear the outputs.
         */
        coins_out = coins();

		/**
  		 * @note Reorganize needs testing.
     	 */

        if (i > 0)
        {
         	for (auto j = m_transactions[i].transactions_in().size(); j-- > 0;)
          	{
           		const auto & out_point =
					m_transactions[i].transactions_in()[j].previous_out()
				;
                
           		const auto & reorganize_data = coins_reorganize_data[j];
          
          		coins coins_cached;
            
            	coins_cache::instance().get_coins(
                	out_point.get_hash(), coins_cached
                );
            
            	if (reorganize_data.height != 0)
             	{
              		if (coins_cached.is_pruned() == false)
                	{
                 		ret = ret && false;
                        
                        log_error(
                            "Block disconnect, reorganize data "
                            "overwriting existing transaction."
                        );
                 	}
              	}
               	else
                {
					if (coins_cached.is_pruned() == true)
                    {
                    	ret = ret && false;
                        
                        log_error(
                            "Block, disconnect, reorganize data "
                            "adding output to missing transaction."
                        );
					}
                }
                
                if (coins_cached.is_available(out_point.n()) == true)
                {
                	ret = ret && false;
                    
                    log_error(
                        "Block, disconnect, reorganize data "
                        "overwriting existing output."
                    );
                }
                
                if (coins_cached.transaction_outs().size() < out_point.n() + 1)
                {
                    coins_cached.transaction_outs().resize(out_point.n() + 1);
                }
                
                coins_cached.transaction_outs()[out_point.n()] =
                	reorganize_data.tx_out
                ;
                
            	if (
					coins_cache::instance().set_coins(
                    out_point.get_hash(), coins_cached) == false
					)
             	{
                    log_error(
                        "Block disconnect failed, cannot restore coin inputs."
                    );

                	return false;
                }
                
				/**
     			 * Update the spends in the transaction so the call to
                 * sync_with_wallets will have the changes.
                 * @note Confirm this works ok.
                 */
                m_transactions[i].transactions_out()[out_point.n()] =
                    reorganize_data.tx_out
                ;
          	}
        }
    }
    
    /**
     * Update block index on disk without changing it in memory. The memory
     * index structure will be changed after the database commits.
     */
    if (index->block_index_previous())
    {
        block_index_disk previous(*index->block_index_previous());

        /**
         * Set the next hash to null.
         */
        previous.set_hash_next(0);
        
        if (tx_db.write_blockindex(previous) == false)
        {
            log_error("Block, disconnect failed, write block index failed");
            
            return false;
        }
    }
    
    /**
     * Move the coins_cache best block_index pointer back to it's parent
     * block_index.
     */
    coins_cache::instance().set_block_index_best(
    	index->block_index_previous()
    );

    /**
     * Clean up wallet after disconnecting.
     */
    for (auto & i : m_transactions)
    {
        wallet_manager::instance().sync_with_wallets(i, this, false, false);
    }
    
    log_info(
    	"Disconnect block " << get_hash().to_string() <<
        " complete ret = " << (ret ? "true" : "false") << "."
    );
    
    return ret;
}

bool block::connect_block_2(
    db_tx & tx_db, block_index * pindex, const bool  & check_only
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not connecting because state != state_started.");
    
        return false;
    }
    
    try
    {
        /**
         * Check it again in case a previous version let a bad block in.
         */
        if (check_block(0, check_only == false, check_only == false) == false)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }
    
    /**
     * Check that the coins_cache best block_index matches the previous
     * block_index of the block we are connecting.
     */
    if (
    	pindex->block_index_previous() !=
        coins_cache::instance().block_index_best()
        )
    {
    	log_error("Block connect failed, coins_cache block index mismatch.");
        
    	throw std::runtime_error("coins_cache block index mismatch");
     
     	return false;
    }
    
    /**
     * Genesis block.
     */
    if (
    	get_hash() == (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
    	)
    {
        coins_cache::instance().set_block_index_best(pindex);
  
    	stack_impl::set_block_index_genesis(pindex);
        
        return true;
    }
    
    static const std::int64_t time_bip30 = 1331769600;
    
    auto enforce_bip30 = pindex->time() > time_bip30;
    
    static const std::int64_t time_bip16 = 1333238400;
    
    auto strict_pay_to_script_hash = pindex->time() > time_bip16;

	/**
	 * BIP30
     */
    if (enforce_bip30 == true)
    {
    	for (auto & i : m_transactions)
     	{
      		if (
        		coins_cache::instance().have_coins(i.get_hash()) &&
                coins_cache::instance().get_coins(
                get_hash()).is_pruned() == false
                )
        	{
         		log_error("Block connect failed, BIP30 enforced.");
                
         		return false;
         	}
      	}
    }

    /**
     * Possible issue here: it doesn't know the version.
     */
    std::uint32_t tx_pos;
    
    if (check_only)
    {
        /**
         * Since we're just checking the block and not actually connecting it,
         * it might not (and probably shouldn't) be on the disk to get the
         * transaction from.
         */
        tx_pos = 1;
    }
    else
    {
        block tmp;
        
        tmp.encode(true);
        
        tx_pos =
            static_cast<std::uint32_t> (pindex->block_position() +
            tmp.size() - 1 + utility::get_var_int_size(m_transactions.size()))
        ;
    }

    /**
     * Allocate the script_checker_queue:context.
     */
    script_checker_queue::context script_checker_queue_context;
    
    std::int64_t fees = 0;
    std::int64_t value_in = 0;
    std::int64_t value_out = 0;
    
    std::uint32_t sig_ops = 0;
    
    double loop_time1 = 0.0;
    double loop_time2 = 0.0;
    
    for (auto & i : m_transactions)
    {
        auto hash_tx = i.get_hash();
        
        sig_ops += i.get_legacy_sig_op_count();
        
        if (sig_ops > block::get_maximum_size() / 50)
        {
            log_error("Block connect block failed, too many sigops.");
            
            return false;
        }
        
        transaction_position tx_position_this(
            pindex->file(), pindex->block_position(), tx_pos
        );
        
        if (check_only == false)
        {
            data_buffer tmp;
        
            i.encode(tmp);
        
            tx_pos += tmp.size();
        }

        if (i.is_coin_base() == true)
        {
            value_out += i.get_value_out();
        }
        else
        {
            auto start_fetch_inputs = std::chrono::system_clock::now();

			/**
             * Check that we have the inputs for this transaction in the
             * coins_cache or coins_database.
             */
			if (i.have_inputs() == false)
   			{
      			log_error("Block connect failed, inputs missing or spent.");
                
      			return false;
      		}
        
            if (strict_pay_to_script_hash)
            {
                /**
                 * Add in sigops done by pay-to-script-hash inputs; this is to
                 * prevent a "rogue miner" from creating an
                 * incredibly-expensive-to-validate block.
                 */

                sig_ops += i.get_p2sh_sig_op_count_2();
                
                if (sig_ops > block::get_maximum_size() / 50)
                {
                    log_error("Block connect failed, too many sig ops.");
                    
                    return false;
                }
            }
            
            std::chrono::duration<double> elapsed_seconds_fetch_inputs =
                std::chrono::system_clock::now() - start_fetch_inputs
            ;
            
            loop_time1 += elapsed_seconds_fetch_inputs.count();

            std::int64_t tx_value_in = i.get_value_in_2();
            std::int64_t tx_value_out = i.get_value_out();
            
            value_in += tx_value_in;
            value_out += tx_value_out;
            
            /**
             * Calculate the fee.
             */
            fees += tx_value_in - tx_value_out;
            
            /**
             * Allocate container to hold all scripts to be verified by the
             * script_checker_queue.
             */
            std::vector<script_checker> script_checker_checks;

            auto start_connect_inputs = std::chrono::system_clock::now();

			/**
   			 * Check the inputs.
       		 */
            if (
                i.check_inputs(true, false, strict_pay_to_script_hash, true,
                &script_checker_checks) == false
                )
            {
				log_error("Block connect failed, check inputs failed.");
                
                return false;
            }
            
            std::chrono::duration<double> elapsed_seconds_connect_inputs =
                std::chrono::system_clock::now() - start_connect_inputs
            ;

            loop_time2 += elapsed_seconds_connect_inputs.count();
            
            /**
             * Insert the scripts to be check by the script_checker_queue.
             */
            script_checker_queue_context.insert(script_checker_checks);
        }

		/**
         * Update the coins in the coins_cache.
         */
        if (i.update_coins(coins_cache::instance(), pindex->height()) == false)
        {
            log_error("Block, connect failed to update coins.");
            
            return false;
        }
    }
    
    log_info(
        "Block connect have inputs took " << loop_time1 << " seconds."
    );
    log_info(
        "Block connect connect inputs took " << loop_time2 << " seconds."
    );
    
    /**
     * Wait for all scripts to be checked by the script_checker_queue.
     */
    if (script_checker_queue_context.sync_wait() == false)
    {
        log_error(
            "Block connect failed, one of the scripts failed validation."
        );
        
        return false;
    }

    /**
     * Set the mint.
     */
    pindex->set_mint(value_out - value_in + fees);
    
    /**
     * Set the money supply.
     */
    pindex->set_money_supply(
        (pindex->block_index_previous() ?
        pindex->block_index_previous()->money_supply() : 0) +
        value_out - value_in
    );

    /**
     * Update the money supply.
     */
    globals::instance().set_money_supply(pindex->money_supply());
    
    block_index_disk new_block_index(*pindex);
    
    if (tx_db.write_blockindex(new_block_index) == false)
    {
        log_error("Block connect failed, write_block_index for failed.");
        
        return false;
    }

    if (check_only)
    {
        return true;
    }

    sha256 hash_previous = 0;
    
    if (pindex->block_index_previous())
    {
        hash_previous = pindex->block_index_previous()->get_block_hash();
    }

    if (
        m_transactions[0].get_value_out() >
        reward::get_proof_of_work(pindex->height(), fees, hash_previous)
        )
    {
        return false;
    }

    /**
     * Update block index on disk without changing it in memory. The memory
     * index structure will be changed after the db commits.
     */
    if (pindex->block_index_previous())
    {
        block_index_disk previous(*pindex->block_index_previous());
        
        previous.set_hash_next(pindex->get_block_hash());
        
        if (tx_db.write_blockindex(previous) == false)
        {
            log_error("Block, connect failed, write_block_index failed.");
         
            return false;
        }
    }
    
    /**
     * Set the coins_cache best block_index.
     */
    coins_cache::instance().set_block_index_best(pindex);

    /**
     * Watch for transactions paying to us.
     */
    for (auto & i : m_transactions)
    {
        wallet_manager::instance().sync_with_wallets(i, this, true);
    }

    return true;
}

bool block::is_proof_of_work() const
{
    return true;
}

std::int64_t block::get_max_transaction_time() const
{
    std::int64_t ret = 0;
    
    for (auto & i : m_transactions)
    {
        ret = std::max(ret, (static_cast<std::int64_t>(i.time())));
    }

    return ret;
}

sha256 block::build_merkle_tree() const
{
    m_merkle_tree.clear();
    
    for (auto & i : m_transactions)
    {
        m_merkle_tree.push_back(i.get_hash());
    }
    
    int j = 0;
    
    for (auto size = m_transactions.size(); size > 1; size = (size + 1) / 2)
    {
        for (auto i = 0; i < size; i += 2)
        {
            auto i2 = std::min(static_cast<std::size_t> (i + 1), size - 1);

            m_merkle_tree.push_back(sha256::from_digest(&hash::sha256d(
                m_merkle_tree[j + i].digest(),
                m_merkle_tree[j + i].digest() + sha256::digest_length,
                m_merkle_tree[j + i2].digest(),
                m_merkle_tree[j + i2].digest() + sha256::digest_length)[0])
            );
        }
        
        j += size;
    }
    
    return m_merkle_tree.empty() ? 0 : m_merkle_tree.back();
}

bool block::is_header_valid()
{
    /**
     * Check the timestamp.
     */
    if (m_header.timestamp > std::time(0) + constants::max_clock_drift)
    {
        log_error(
            "Block header timestamp too far in the future (" <<
            m_header.timestamp << ":" <<
            std::time(0) + constants::max_clock_drift << ")."
        );
     
        return false;
    }

    if (check_proof_of_work(get_hash(), m_header.bits) == false)
    {
        log_error("Block header check Proof-of-Work failed.");
        
        return false;
    }
    
    return true;
}

void block::set_peer_headers_first_sync_height(const std::int32_t & val)
{
	m_peer_headers_first_sync_height = val;
}

const std::int32_t & block::peer_headers_first_sync_height() const
{
	return m_peer_headers_first_sync_height;
}

bool block::check_block(
    const std::shared_ptr<tcp_connection> & connection, const bool & check_pow,
    const bool & check_merkle_root
    )
{
    /**
     * These are checks that are independent of context that can be verified
     * before saving an orphan block.
     */
    
    /**
     * Clear
     */
    clear();
    
    /**
     * Encode
     */
    encode();
    
    /**
     * Get the size.
     */
    auto length = size();
    
    /**
     * Clear
     */
    clear();
    
    /**
     * Check size limits.
     */
    if (
        m_transactions.size() == 0 ||
        m_transactions.size() > block::get_maximum_size() ||
        length > block::get_maximum_size()
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("size limits failed");
        
        return false;
    }

    /**
     * Check that the nonce is in range for the block type.
     */
    if (is_proof_of_work() == true)
    {
        if (m_header.nonce == 0)
        {
            throw std::runtime_error("invalid nonce for proof of work");
            
            return false;
        }
    }

    /**
     * Check that the proof of work matches claimed amount.
     */
    if (
        check_pow && is_proof_of_work() &&
        check_proof_of_work(get_hash(), m_header.bits) == false
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(50);
        }
        
        throw std::runtime_error("proof of work failed");
     
        return false;
    }

    /**
     * Check the timestamp.
     */
    if (
        m_header.timestamp >
        time::instance().get_adjusted() + constants::max_clock_drift
        )
    {
        throw std::runtime_error("block timestamp too far in the future");
     
        return false;
    }

    /**
     * The first transaction must be coinbase.
     */
    if (
        m_transactions.size() == 0 || m_transactions[0].is_coin_base() == false
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error(
            m_transactions.size() == 0 ? "first tx is missing" :
            "first tx is not coinbase"
        );
     
        return false;
    }
    
    for (auto i = 1; i < m_transactions.size(); i++)
    {
        if (m_transactions[i].is_coin_base())
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(100);
            }
            
            throw std::runtime_error("more than one coinbase");
         
            return false;
        }
    }
    
#if 0 /** Commented out in the original code. */
    /**
     * Check the coinbase timestamp.
     */
    if (
        m_header.timestamp > m_transactions[0].time() +
        constants::max_clock_drift
        )
    {
        log_error(
            "Block failed to check coinbase timestamp because it "
            "is too early."
        );
         
        return false;
    }
#endif

    /**
     * Check the transactions.
     */
    for (auto & i : m_transactions)
    {
        if (i.check() == false)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(connection->dos_score() + 1);
            }
            
            throw std::runtime_error("check_transaction failed");
             
            return false;
        }
    }

    /**
     * Check for duplicate tx id's. This is caught by connect_inputs, but
     * catching it earlier avoids a potential DoS attack.
     */
    std::set<sha256> unique_tx;

    for (auto & i : m_transactions)
    {
        unique_tx.insert(i.get_hash());
    }
    
    if (unique_tx.size() != m_transactions.size())
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("duplicate transaction");
         
        return false;
    }

    auto sig_ops = 0;
    
    for (auto & i : m_transactions)
    {
        sig_ops += i.get_legacy_sig_op_count();
    }
    
    if (sig_ops > block::get_maximum_size() / 50)
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("sig ops out-of-bounds");
        
        return false;
    }
    
    /**
     * Check merkle root.
     */
    if (check_merkle_root && m_header.hash_merkle_root != build_merkle_tree())
    {
        log_error(
            "Block merkle root mismatch " <<
            m_header.hash_merkle_root.to_string() << ":" <<
            build_merkle_tree().to_string() << ""
        );
        
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("hash merkle root mismatch");
        
        return false;
    }

    return true;
}

bool block::read_from_disk(
    const block_index * index, const bool & read_transactions
    )
{
    if (read_transactions == false)
    {
        *this = index->get_block_header();
        
        return true;
    }
    
    if (
        read_from_disk(index->file(), index->block_position(),
        read_transactions) == false
        )
    {
        return false;
    }
    
    if (get_hash() != index->get_block_hash())
    {
        throw std::runtime_error("get_hash doesn't match index");
        
        return false;
    }
    
    return true;
}

/**
 * @note Possibly move to utility class.
 */
static bool is_super_majority(
    const std::uint32_t & version_minimum, const block_index * ptr_block_index,
    const std::uint32_t & required = 950, const std::uint32_t & window = 1000
    )
{
    auto index = 0;
    
    for (
        auto i = 0; i < window && index < required && ptr_block_index != 0; i++
        )
    {
        if (
            ptr_block_index->get_block_header(
            ).header().version >= version_minimum
            )
        {
            ++index;
        }
        
        ptr_block_index = ptr_block_index->block_index_previous();
    }
    
    return index >= required;
}

bool block::accept_block(
    const std::shared_ptr<tcp_connection_manager> & connection_manager
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_debug("Block, not accepting because state != state_started.");
    
        return false;
    }
    
    if (globals::instance().is_client_spv() == true)
    {
        log_debug("Block, not accepting because we are an SPV client.");
        
        return false;
    }
    
    auto hash_block = get_hash();
 
    /**
     * Check for duplicate.
     */
    if (globals::instance().block_indexes().count(hash_block) > 0)
    {
        log_error("Block, accept block failed, already in block indexes.");
    
        return false;
    }
    
    /**
     * Get the previous block index.
     */
    auto it = globals::instance().block_indexes().find(
        m_header.hash_previous_block
    );
    
    if (it == globals::instance().block_indexes().end())
    {
        log_error(
            "Block, accept block failed, previous block " <<
            m_header.hash_previous_block.to_string().substr(0, 20) <<
            " not found."
        );
    
        return false;
    }
    
    /**
     * Get the previous index.
     */
    auto index_previous = it->second;

    /**
     * Get the height.
     */
    auto height = index_previous->height() + 1;
    
    log_debug("Block, accept block, height = " << height << ".");
    
    auto bits = utility::get_next_target_required(index_previous, this);

    /**
     * Check the proof-of-work or the proof-of-work.
     */
    if (m_header.bits != bits)
    {
        log_error(
            "Block, accept block failed, incorrect proof-of-work."
        );
        
        return false;
    }

    /**
     * Check the timestamp (time-too-old).
     */
    if (m_header.timestamp <= index_previous->get_median_time_past())
    {
        log_error(
            "Block, accept block failed, block's timestamp is too early "
            "(time-too-old)."
        );
    
        return false;
    }
    
    /**
     * Check the timestamp (time-too-new).
     */
    if (
        m_header.timestamp >
        time::instance().get_adjusted() + constants::max_clock_drift
        )
    {
        log_error(
            "Block, accept block failed, block's timestamp too far in the "
            "future (time-too-new)."
        );
    
        return false;
    }
    
    /**
     * Check that all transactions are finalized.
     */
    for (auto & i : m_transactions)
    {
        if (i.is_final(height, m_header.timestamp) == false)
        {
            log_error(
                "Block, accept block failed, contains a non-final transaction."
            );
         
            return false;
        }
    }
    
    /**
     * Check that the block chain matches the known block chain up to a
     * checkpoint.
     */
    if (checkpoints::instance().check_hardened(height, hash_block) == false)
    {
        log_error(
            "Block, accept block failed, rejected by hardened checkpoint "
            "lock-in at " << height << "."
        );
    
        return false;
    }

    /**
     * Reject block's by header version.
     */

    if (
        m_header.version < 2 &&
        is_super_majority(2, index_previous,
        constants::test_net  == true ? 75 : 950,
        constants::test_net == true ? 100 : 1000)
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 2."
        );
    
        return false;
    }

    if (
        m_header.version < 3 &&
        is_super_majority(3, index_previous,
        constants::test_net  == true ? 75 : 950,
        constants::test_net == true ? 100 : 1000)
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 3."
        );
    
        return false;
    }

    if (
        m_header.version < 4 &&
        is_super_majority(4, index_previous,
        constants::test_net  == true ? 75 : 950,
        constants::test_net == true ? 100 : 1000)
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 4."
        );
    
        return false;
    }

    /**
     * BIP-034
     */
    if (
        m_header.version >= 2 &&
        is_super_majority(2, index_previous,
        constants::test_net  == true ? 51 : 750,
        constants::test_net == true ? 100 : 1000)
        )
    {
        /**
         * Enforce rule that the coinbase starts with serialized block height.
         */
        script expect = script() << height;
        
        if (
            std::equal(expect.begin(), expect.end(),
            m_transactions[0].transactions_in()[0].script_signature().begin()
            ) == false
            )
        {
            log_error(
                "Block, accept block failed, block height mismatch in coinbase."
            );
        
            return false;
        }
    }
    
    /**
     * Write block to history file.
     */
    
    /**
     * Allocate a temporary buffer to determine the size of the block in bytes.
     */
    data_buffer buffer;
    
    /**
     * Encode ourselves into the buffer.
     */
    encode(buffer);
    
    /**
     * Get the available disk space.
     */
    auto disk_available =
        utility::disk_info(filesystem::data_path()).available
    ;
    
    /**
     * Make sure we have enough disk space.
     */
    if (disk_available < buffer.size())
    {
        log_error(
            "Block, accept block failed, out of disk space, "
            "available = " << disk_available << "."
        );
        
        return false;
    }
    
    std::uint32_t file = -1;
    
    std::uint32_t block_position = 0;
    
    /**
     * Write the block to disk.
     */
    if (write_to_disk(file, block_position) == false)
    {
        log_error("Block, accept block failed, write_to_disk failed.");
        
        return false;
    }

    /**
     * Add the block to the index.
     */
    if (add_to_block_index(file, block_position) == false)
    {
        log_error("Block, accept block failed, add_to_block_index failed.");
        
        return false;
    }

    /**
     * Do not relay during initial download.
     */
    if (utility::is_initial_block_download() == false)
    {
        /**
         * Relay inventory.
         */
        if (globals::instance().hash_best_chain() == hash_block)
        {
            if (connection_manager)
            {
                auto connections = connection_manager->tcp_connections();
                
                for (auto & i : connections)
                {
                    if (auto connection = i.second.lock())
                    {
						if (
      	                  globals::instance(
                            ).peer_use_headers_first_chain_sync() == true &&
                            connection->is_sendheaders() == true
                            )
      					{
                            /**
                             * Relay the next block header after the last
                             * header this peer has requested including our
                             * best block header (if not redundant).
                             */
                            const block_index *
                                block_index_best_block_header_sent = nullptr
                            ;
                            
                            if (
                                globals::instance().block_indexes().count(
                                connection->hash_best_block_header_sent()) > 0
                                )
                            {
                                block_index_best_block_header_sent =
                                	globals::instance().block_indexes()[
                                    connection->hash_best_block_header_sent()]
                                ;
                            }
                            
                            std::vector<block> headers;
                            
                            if (block_index_best_block_header_sent != nullptr)
                            {
                                auto b1 =
									block_index_best_block_header_sent->block_index_next(
                                    )->get_block_header()
                                ;
                            
                                auto b2 =
                                   stack_impl::get_block_index_best(
                                   )->get_block_header()
                                ;
                             
                             	if (b1.get_hash() == b2.get_hash())
                              	{
                             		headers.push_back(b1);
								}
                                else
                                {
                             		headers.push_back(b1);
                               		headers.push_back(b2);
                                }
                            }
                            
                            if (headers.size() > 0)
                            {
                            	log_info(
                             	   "Block, accepted new, relaying " <<
                                    headers.size() << " headers to peer " <<
                                    connection->identifier() << "."
                                );
                                
                            	connection->send_headers_message(headers);
                            }
           				}
               			else
                  		{
                            connection->send_inv_message(
                                inventory_vector::type_msg_block, hash_block
                            );
                    	}
                    }
                }
            }
        }
    }
    
    return true;
}

bool block::read_from_disk(
    const std::uint32_t & file_index, const std::uint32_t & block_position,
    const bool & read_transactions
    )
{
    set_null();

    auto f = file_open(file_index, block_position, "rb");
    
    if (f)
    {
        auto block_header_only = false;
        
        if (read_transactions == false)
        {
            block_header_only = true;
        }
        
        /**
         * Clear the buffer.
         */
        clear();

        /**
         * Set the file for decoding.
         */
        set_file(f);

        /**
         * Attempt to decode.
         */
        if (decode(block_header_only))
        {
            /**
             * Clear the buffer.
             */
            clear();
        
            /**
             * Close the file.
             */
            f->close();
            
            /**
             * Set the file to null.
             */
            set_file(nullptr);
        }
        else
        {
            /**
             * Set the file to null.
             */
            set_file(nullptr);
        
            return false;
        }
        
        /**
         * Check the header.
         */
        if (read_transactions)
        {
            if (is_proof_of_work())
            {
                if (check_proof_of_work(get_hash(), m_header.bits) == false)
                {
                    log_error(
                        "Block check proof of work failed, errors in "
                        "block header."
                    );
                    
                    return false;
                }
            }
        }
    }
    else
    {
        log_error("Block failed to open block file.");
        
        return false;
    }

    return true;
}

bool block::write_to_disk(
    std::uint32_t & file_number, std::uint32_t & block_position
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not writing to disk because state != state_started.");
    
        return false;
    }
     
    /**
     * Open history file to append.
     */
    auto f = file_append(file_number);
    
    if (f)
    {
        /**
         * Allocate the buffer.
         */
        data_buffer buffer_block;
        
        /**
         * Encode the block into the buffer.
         */
        encode(buffer_block);
        
        /**
         * Get the size of the buffer.
         */
        std::uint32_t size = static_cast<std::uint32_t> (buffer_block.size());
        
        /**
         * Get the magic (message start).
         */
        std::uint32_t magic = message::header_magic();
        
        /**
         * Allocate the index buffer.
         */
        data_buffer buffer_index;
        
        /**
         * Write the magic (message start).
         */
        buffer_index.write_uint32(magic);
        
        /**
         * Write the encoded block size.
         */
        buffer_index.write_uint32(size);
        
        /**
         * Write the index header buffer.
         */
        f->write(buffer_index.data(), buffer_index.size());

        /**
         * Get the out position.
         */
        auto out_position = f->ftell();
        
        if (out_position < 0)
        {
            log_error("Block failed writing to disk, ftell failed");
            
            return false;
        }
        
        /**
         * Set the block position to the out position.
         */
        block_position = static_cast<std::uint32_t> (out_position);

        /**
         * Write the block buffer.
         */
        f->write(buffer_block.data(), buffer_block.size());

        /**
         * Flush
         */
        f->fflush();

        /**
         * Sync the file to disk.
         */
        if (
            utility::is_initial_block_download() == false ||
            (globals::instance().best_block_height() + 1) % 500 == 0
            )
        {
            f->fsync();
        }
    }
    else
    {
        log_error("Block failed writing to disk, file append failed.");
        
        return false;
    }

    return true;
}

bool block::set_best_chain(db_tx & tx_db, block_index * index_new)
{
    auto block_hash = get_hash();

    if (tx_db.txn_begin() == false)
    {
        log_error("Block, set best chain failed, txn_begin failed.");
        
        return false;
    }
    
    if (
        stack_impl::get_block_index_genesis() == 0 &&
        block_hash == (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
        )
    {
        tx_db.write_hash_best_chain(block_hash);
        
        if (tx_db.txn_commit() == false)
        {
            log_error("Block set best chain txn_commit failed.");
            
            return false;
        }
        
        stack_impl::set_block_index_genesis(index_new);
    }
    else if (
        m_header.hash_previous_block == globals::instance().hash_best_chain()
        )
    {
        if (set_best_chain_inner(tx_db, index_new) == false)
        {
            log_error("Block set best chain inner failed.");
            
            return false;
        }
    }
    else
    {
        /**
         * The first block in the new chain that will cause it to become the
         * new best chain.
         */
        auto index_intermediate = index_new;

        /**
         * List of blocks that need to be connected afterwards.
         */
        std::vector<block_index *> index_secondary;

        /**
         * Reorganization is costly in terms of database load because it works
         * in a single database transaction. We try to limit how much needs
         * to be done inside.
        */
        while (
            index_intermediate->block_index_previous() &&
            index_intermediate->block_index_previous()->chain_trust() >
            stack_impl::get_block_index_best()->chain_trust()
            )
        {
            index_secondary.push_back(index_intermediate);
            
            index_intermediate =
                index_intermediate->block_index_previous()
            ;
        }

        if (index_secondary.size() > 0)
        {
            log_debug(
                "Block set best chain is postponing " <<
                index_secondary.size() << " reconnects."
            );
        }
        
        /**
         * Connect further blocks.
         */
        for (auto & i : index_secondary)
        {
            block blk;
            
            if (blk.read_from_disk(i) == false)
            {
                log_error(
                    "Block failed to set best chain, read_from_disk failed."
                );

                break;
            }
            
            if (tx_db.txn_begin() == false)
            {
                log_error(
                    "Block failed to set best chain, txn_begin failed."
                );
               
                break;
            }
            
            /**
             * Errors are no longer fatal, we still did a reorganization to a
             * new chain in a valid way.
             */
            if (blk.set_best_chain_inner(tx_db, i) == false)
            {
                break;
            }
        }
    }
    
    /**
     * Update best block in wallet (so we can detect restored wallets).
     */
    auto is_initial_download = utility::is_initial_block_download();
    
    if (is_initial_download == false)
    {
        /**
         * Notify wallets about a new best chain.
         */
        wallet_manager::instance().set_best_chain(block_locator(index_new));
    }
    
    /**
     * New best block.
     */
    globals::instance().set_hash_best_chain(block_hash);
    stack_impl::set_block_index_best(index_new);
    globals::instance().set_block_index_fbbh_last(nullptr);
    globals::instance().set_best_block_height(
        stack_impl::get_block_index_best()->height()
    );
    stack_impl::get_best_chain_trust() = index_new->chain_trust();
    globals::instance().set_time_best_received(std::time(0));
    globals::instance().set_transactions_updated(
        globals::instance().transactions_updated() + 1
    );

    log_debug(
        "Block, set best chain, new best = " <<
        globals::instance().hash_best_chain().to_string() <<
        ", height = " << globals::instance().best_block_height() <<
        ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
        ", date = " << stack_impl::get_block_index_best()->time() << "."
    );

    if (globals::instance().best_block_height() % 8 == 0)
    {
        log_info(
            "Block, set best chain, new best = " <<
            globals::instance().hash_best_chain().to_string() <<
            ", height = " << globals::instance().best_block_height() <<
            ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
            ", date = " << stack_impl::get_block_index_best()->time() << "."
        );
    }

    /**
     * Check the version of the last 100 blocks to see if we need to upgrade.
     */
    if (utility::is_initial_block_download() == false)
    {
        auto blocks_upgraded = 0;
        
        auto index = stack_impl::get_block_index_best();
        
        std::uint32_t version_expected = 0;
        
        for (auto i = 0; i < 100 && index != 0; i++)
        {
            version_expected =
                version_bits::instance().block_version_compute(
                index->block_index_previous(),
                version_bits::instance().parameters())
            ;
            
            enum { version_before_version_bits = 4 };
            
            if (
                index->version() > version_before_version_bits &&
                (index->version() & ~version_expected) != 0
                )
            {
                ++blocks_upgraded;
            }
            
            index = index->block_index_previous();
        }
        
        if (blocks_upgraded > 0)
        {
            log_info(
                "Block set best chain, " << blocks_upgraded <<
                " of last 100 blocks version = " << index->version() <<
                ", expected = " << version_expected << "."
            );
        }
        
        if (blocks_upgraded / 2 > 100)
        {
            log_warn(
                "Block detected unkown version, unkown version bit rules "
                "may be in effect."
            );
        }
    }

    /*
     * -blocknotify
     */

    return true;
}

bool block::set_best_chain_2(db_tx & tx_db, block_index * index_new)
{
    /**
     * Find the fork.
     */
    auto * fork = coins_cache::instance().block_index_best();
    
    auto * longer = index_new;
    
    while (fork && fork != longer)
    {
        while (longer->height() > fork->height())
        {
            if (!(longer = longer->block_index_previous()))
            {
                log_error(
                    "Block set best chain failed, (longer) previous block "
                    "index is null."
                );
                
                return false;
            }
        }
        
        if (fork == longer)
        {
            break;
        }
        
        if (!(fork = fork->block_index_previous()))
        {
            log_error(
                "Block set best chain failed, (fork) previous block "
                "index is null."
            );
            
            return false;
        }
    }
    
    /**
     * List of what to disconnect.
     */
    std::vector<block_index *> to_disconnect;
    
    for (
        auto * index = coins_cache::instance().block_index_best();
        index != fork; index = index->block_index_previous()
        )
    {
        to_disconnect.push_back(index);
    }

    /**
     * List of what to connect.
     */
    std::vector<block_index *> to_connect;

    for (
        auto * index = index_new; index != fork;
        index = index->block_index_previous()
        )
    {
        to_connect.push_back(index);
    }
    
    std::reverse(to_connect.begin(), to_connect.end());
    
    if (to_disconnect.size() > 0)
    {
        log_info(
            "Block, reorganize is disconnecting " << to_disconnect.size() <<
            " blocks: " << fork->get_block_hash().to_string() << "."
        );
        
        log_info(
            "Block, reorganize is connecting " << to_connect.size() <<
            " blocks: " << index_new->get_block_hash().to_string().substr() <<
            "."
        );
    }
    
    /**
     * Disconnect shorter branch.
     */
    std::vector<transaction> to_resurrect;
    
    for (auto & i : to_disconnect)
    {
        block blk;
        
        if (blk.read_from_disk(i) == false)
        {
            log_error("Block, set best chain failed to read from disk.");
            
            return false;
        }

        if (blk.disconnect_block_2(tx_db, i) == false)
        {
            log_error(
                "Block, set best chain failed, disconnect_block_2 failed " <<
                i->get_block_hash().to_string().substr(0, 20) << "."
            );
            
            return false;
        }

        /**
         * Queue memory transactions to resurrect.
         */
        for (auto & j : blk.transactions())
        {
            if (
            	j.is_coin_base() == false && i->height() >
             	checkpoints::instance().get_total_blocks_estimate()
             	)
            {
                to_resurrect.push_back(j);
            }
        }
    }
    
    /**
     * Connect longer branch.
     */
    std::vector<transaction> to_delete;
    
    for (auto i = 0; i < to_connect.size(); i++)
    {
        auto & pindex = to_connect[i];
        
        block blk;
        
        if (blk.read_from_disk(pindex) == false)
        {
            log_error(
                "Block, set best chain failed, read_from_disk for connect "
                "failed."
            );
        
            return false;
        }

        if (blk.connect_block_2(tx_db, pindex) == false)
        {
            /**
             * We have found a bad block chain.
             */
            block::invalid_chain_found(pindex);
            
            /**
             * Invalid block.
             */
            log_error(
                "Block, set best chain failed, connect_block_2 " <<
                pindex->get_block_hash().to_string() << " failed."
            );
            
            return false;
        }

        /**
         * Queue memory transactions to delete.
         */
        for (auto & i : blk.transactions())
        {
            to_delete.push_back(i);
        }
    }
    
    /**
     * Flush the coins_cache coins_database to disk.
     * @note Do not clear the in-memory cache.
     */
    coins_cache::instance().flush(false);
    
    /**
     * Make sure it's successfully written to disk before changing memory
     * structure.
     */
	if (
		utility::is_initial_block_download() == false ||
		coins_cache::instance().size() > coins_cache::minimum
		)
   	{
    	/**
     	 * Flush the coins_cache coins_database to disk.
      	 * @note Clear the in-memory cache.
    	 */
        if (coins_cache::instance().flush(true) == false)
        {
        	log_error("Block, set best chain failed to flush coins cache.");
        }
    }
    
    /**
     * Disconnect shorter branch.
     */
    for (auto & i : to_disconnect)
    {
        if (i->block_index_previous())
        {
            i->block_index_previous()->set_block_index_next(nullptr);
        }
    }
    
    /**
     * Connect longer branch.
     */
    for (auto & i : to_connect)
    {
        if (i->block_index_previous())
        {
            i->block_index_previous()->set_block_index_next(i);
        }
    }
    
    /**
     * Resurrect memory transactions that were in the disconnected branch.
     */
    for (auto & i : to_resurrect)
    {
        i.accept_to_transaction_pool_2();
    }
    
    /**
     * Delete redundant memory transactions that are in the connected branch.
     */
    for (auto & i : to_delete)
    {
        transaction_pool::instance().remove(i);
        
        /**
         * @note Do we still need this?
         * transaction_pool::instance().remove_confilcts(i);
         */
    }
    
    /**
     * Update best block in wallet (so we can detect restored wallets).
     */
    auto is_initial_download = utility::is_initial_block_download();
    
    if (is_initial_download == false)
    {
        /**
         * Notify wallets about a new best chain.
         */
        wallet_manager::instance().set_best_chain(block_locator(index_new));
    }
    
    /**
     * New best block.
     */
    globals::instance().set_hash_best_chain(index_new->get_block_hash());
    stack_impl::set_block_index_best(index_new);
    globals::instance().set_block_index_fbbh_last(nullptr);
    globals::instance().set_best_block_height(
        stack_impl::get_block_index_best()->height()
    );
    stack_impl::get_best_chain_trust() = index_new->chain_trust();
    globals::instance().set_time_best_received(std::time(0));
    globals::instance().set_transactions_updated(
        globals::instance().transactions_updated() + 1
    );

    log_info(
        "Block, set best chain, new best = " <<
        globals::instance().hash_best_chain().to_string() <<
        ", height = " << globals::instance().best_block_height() <<
        ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
        ", date = " << stack_impl::get_block_index_best()->time() << "."
    );

    /**
     * Check the version of the last 100 blocks to see if we need to upgrade.
     */
    if (is_initial_download == false)
    {
        auto blocks_upgraded = 0;
        
        auto index = stack_impl::get_block_index_best();
        
        std::uint32_t version_expected = 0;
        
        for (auto i = 0; i < 100 && index != 0; i++)
        {
            version_expected =
                version_bits::instance().block_version_compute(
                index->block_index_previous(),
                version_bits::instance().parameters())
            ;
            
            enum { version_before_version_bits = 4 };
            
            if (
                index->version() > version_before_version_bits &&
                (index->version() & ~version_expected) != 0
                )
            {
                ++blocks_upgraded;
            }
            
            index = index->block_index_previous();
        }
        
        if (blocks_upgraded > 0)
        {
            log_info(
                "Block set best chain, " << blocks_upgraded <<
                " of last 100 blocks version = " << index->version() <<
                ", expected = " << version_expected << "."
            );
        }
        
        if (blocks_upgraded / 2 > 100)
        {
            log_warn(
                "Block detected unkown version, unkown version bit rules "
                "may be in effect."
            );
        }
    }
	
    /*
     * -blocknotify
     */

    return true;
}

bool block::add_to_block_index(
    const std::uint32_t & file_index, const std::uint32_t & block_position
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not adding to index because state != state_started.");
    
        return false;
    }
    
    /**
     * Check for duplicate.
     */
    auto hash_block = get_hash();
    
    if (globals::instance().block_indexes().count(hash_block) > 0)
    {
        log_error(
            "Block add to block index failed, " <<
            hash_block.to_string().substr(0, 20) << " already exists."
        );
        
        return false;
    }
    
    /**
     * Construct new block index.
     */
    auto index_new = new block_index(file_index, block_position, *this);
    
    if (index_new == 0)
    {
        log_error("Block add to block index failed, allocation failure.");
        
        return false;
    }
    
    index_new->set_hash_block(hash_block);
    
    auto it1 = globals::instance().block_indexes().find(
        m_header.hash_previous_block
    );
    
    if (it1 != globals::instance().block_indexes().end())
    {
        index_new->set_block_index_previous(it1->second);

        index_new->set_height(it1->second->height() + 1);
    }
    
    /**
     * Compute chain trust score (ppcoin).
     */
    index_new->set_chain_trust(
        (index_new->block_index_previous() ?
        index_new->block_index_previous()->chain_trust() : 0) +
        index_new->get_block_trust()
    );
    
    /**
     * Add to the block indexes.
     */
    globals::instance().block_indexes().insert(
        std::make_pair(hash_block, index_new)
    );

    /**
     * Write to disk block index.
     */
    db_tx tx_db;
    
    if (tx_db.txn_begin() == false)
    {
        return false;
    }
    
    /**
     * Write the blockindex.
     */
    tx_db.write_blockindex(block_index_disk(*index_new));
    
    if (tx_db.txn_commit() == false)
    {
        return false;
    }
    
    /**
     * Check if we have a new best chain.
     */
    if (index_new->chain_trust() > stack_impl::get_best_chain_trust())
    {
        /**
         * Set the new best chain.
         */
        if (set_best_chain_2(tx_db, index_new) == false)
        {
            return false;
        }
    }
    
    tx_db.close();

    if (index_new == stack_impl::get_block_index_best())
    {
        /**
         * The hash of the previous best coinbase.
         */
        static sha256 g_hash_previous_best_coinbase;
        
        /**
         * Inform the wallet that the transacton was updated.
         */
        wallet_manager::instance().on_transaction_updated(
            g_hash_previous_best_coinbase
        );
        
        g_hash_previous_best_coinbase = m_transactions[0].get_hash();
    }
    
    return true;
}

bool block::set_best_chain_inner(db_tx & tx_db, block_index * index_new)
{
    if (globals::instance().state() != globals::state_started)
    {
    	log_error(
     	   "Block, not setting best chain inner because state "
            "!= state_started."
        );
        
    	return false;
    }

    if (
        connect_block_2(tx_db, index_new) == false ||
        tx_db.write_hash_best_chain(get_hash()) == false
        )
    {
        tx_db.txn_abort();
        
        invalid_chain_found(index_new);
        
        return false;
    }
    
    if (tx_db.txn_commit() == false)
    {
        log_error("Block set best chain inner failed, txn_commit failed.");
        
        return false;
    }
    
    /**
     * Add to current best branch.
     */
    index_new->block_index_previous()->set_block_index_next(index_new);

    /**
     * Delete redundant memory transactions.
     */
    for (auto & i : m_transactions)
    {
        transaction_pool::instance().remove(i);
    }

    return true;
}

void block::invalid_chain_found(const block_index * index_new)
{
    if (index_new->chain_trust() > stack_impl::get_best_invalid_trust())
    {
        stack_impl::get_best_invalid_trust() = index_new->chain_trust();
        
        db_tx().write_best_invalid_trust(stack_impl::get_best_invalid_trust());
    }

    log_info(
        "Block, invalid chain found, invalid block = " <<
        index_new->get_block_hash().to_string().substr(0, 20) <<
        ", height = " << index_new->height() <<
        ", trust = " << index_new->chain_trust().to_string() <<
        ", date = " << index_new->time() << "."
    );

    log_info(
        "Block, invalid chain found, current block = " <<
        globals::instance().hash_best_chain().to_string().substr(0, 20) <<
        ", height = " << globals::instance().best_block_height() <<
        ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
        ", date = " << stack_impl::get_block_index_best()->time() << "."
    );
}

std::size_t block::get_maximum_size()
{
    /**
     * (SPV) clients do not have a maximum block size.
     */
    if (globals::instance().is_client_spv() == true)
    {
        return std::numeric_limits<std::size_t>::max();
    }
#define BCASH_STRESS_TEST 1
#if (defined BCASH_STRESS_TEST && BCASH_STRESS_TEST)
    /**
     * The maximum allowed size for a block, in bytes (network rule).
     */
    return 1000000 * 32;
#else
    /**
     * The maximum allowed size for a block excluding witness data,
     * in bytes (network rule).
     */
    return 1000000 * 1;
#endif
}

std::string block::get_file_path(const std::uint32_t & file_index)
{
    std::stringstream ss;
    
    std::string block_path = "blockchain/peer/";
    
    ss <<
        filesystem::data_path() << block_path <<
        boost::format("blk%04u.dat") % file_index
    ;

    return ss.str();
}

std::shared_ptr<file> block::file_open(
    const std::uint32_t & index, const std::uint32_t & position,
    const char * mode
    )
{
    if ((index < 1) || (index == (std::uint32_t)-1))
    {
        return std::shared_ptr<file> ();
    }
    else
    {
        auto ret = std::make_shared<file>();
        
        if (ret->open(get_file_path(index).c_str(), mode))
        {
            if (position != 0 && !strchr(mode, 'a') && !strchr(mode, 'w'))
            {
                if (ret->seek_set(position) != 0)
                {
                    ret->close();
                    
                    return std::shared_ptr<file> ();
                }
            }
        }
        else
        {
            return std::shared_ptr<file> ();
        }
        
        return ret;
    }
    
    return std::shared_ptr<file> ();
}

std::shared_ptr<file> block::file_append(std::uint32_t & index)
{
    index = 0;
    
    static std::uint32_t current_block_file = 1;
    
    for (;;)
    {
        if (auto f = file_open(current_block_file, 0, "ab"))
        {
            if (f->seek_end() == true)
            {
                /**
                 * The default maximum size is 128 megabytes.
                 */
                std::size_t max_file_size = 128;
                
                max_file_size *= 1000000;

                if (ftell(f->get_FILE()) <= max_file_size)
                {
                    index = current_block_file;
                    
                    return f;
                }

                f->close();
                
                current_block_file++;
            }
            else
            {
                return std::shared_ptr<file> ();
            }
        }
        else
        {
            return std::shared_ptr<file> ();
        }
    }
    
    return std::shared_ptr<file> ();
}

bool block::check_proof_of_work(const sha256 & hash, const std::uint32_t & bits)
{
    /**
     * The genesis block does not use Proof-of-Work, instead a
     * hard-coded hash of it is used.
     */
    if (constants::test_net == true && hash == get_hash_genesis_test_net())
    {
        return true;
    }
    else if (hash == get_hash_genesis())
    {
        return true;
    }
    
    /**
     * Allocate the target
     */
    big_number target;
    
    /**
     * Set the compact bits.
     */
    target.set_compact(bits);

    /**
     * Check the range.
     */
    if (target <= 0 || target > constants::proof_of_work_limit)
    {
        throw std::runtime_error("number of bits below minimum work");

        return false;
    }

    /**
     * Check the proof of work matches the claimed amount.
     */
    if (hash > target.get_sha256())
    {
        log_error(
            "Block check proof of work failed, hash doesn't match bits." <<
            hash.to_string() << ":" << target.get_sha256().to_string()
        );
        
        return false;
    }

    return true;
}

std::vector<sha256> block::get_merkle_branch(std::int32_t index) const
{
    if (m_merkle_tree.size() == 0)
    {
        build_merkle_tree();
    }
    
    std::vector<sha256> merkle_branch;
    
    int j = 0;
    
    for (
        auto size = m_transactions.size(); size > 1;
        size = (size + 1) / 2
        )
    {
        auto i = std::min(index ^ 1, static_cast<std::int32_t> (size - 1));
        
        merkle_branch.push_back(m_merkle_tree[j + i]);
        
        index >>= 1;
        
        j += size;
    }
    
    return merkle_branch;
}

sha256 block::check_merkle_branch(
    sha256 h, const std::vector<sha256> & merkle_branch,
    std::int32_t index
    )
{
    if (index == -1)
    {
        return 0;
    }
    
    for (auto & i : merkle_branch)
    {
        if (index & 1)
        {
            h = sha256::from_digest(&hash::sha256d(
                i.digest(), i.digest() + sha256::digest_length,
                h.digest(), h.digest() + sha256::digest_length)[0]
            );
        }
        else
        {
            h = sha256::from_digest(&hash::sha256d(
                h.digest(), h.digest() + sha256::digest_length,
                i.digest(), i.digest() + sha256::digest_length)[0]
            );
        }
        
        index >>= 1;
    }
    
    return h;
}

void block::print()
{
    std::stringstream ss_transactions;

    for (auto & i : m_transactions)
    {
        ss_transactions << " ";
        ss_transactions << i.to_string();
    }
    
    std::stringstream ss_merkle_tree;
    
    for (auto & i : m_merkle_tree)
    {
        ss_merkle_tree << " ";
        ss_merkle_tree << i.to_string().substr(0, 8);
    }
    
    log_debug(
        "Block, hash = " << get_hash().to_string() << ". version = " <<
        m_header.version << ", hash_previous_block = " <<
        m_header.hash_previous_block.to_string() << ", hash_merkle_root = " <<
        m_header.hash_merkle_root.to_string() << ", timestamp = " <<
        m_header.timestamp << ", bits = " << m_header.bits << ", nonce = " <<
        m_header.nonce << ", transactions = " << m_transactions.size() <<
        ", signature = " << (m_signature.size() > 0 ?
        utility::hex_string(m_signature.begin(), m_signature.end()) : "null") <<
        ", transactions = " << ss_transactions.str() <<
        ", merkle tree = " << ss_merkle_tree.str() << "."
    );
}

int block::run_test()
{
    auto f1 = block::file_open(1, 0, "rb");
    
    if (f1)
    {
        printf("block::run_test: test 1 passed!\n");
    }
    
    std::uint32_t index = 1;
    
    auto f2 = block::file_append(index);
    
    if (f2)
    {
        printf("block::run_test: test 2 passed!\n");
    }
    
    return 0;
}
