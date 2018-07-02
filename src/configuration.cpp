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
#include <fstream>
#include <limits>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/android.hpp>
#include <coin/configuration.hpp>
#include <coin/globals.hpp>
#include <coin/db_env.hpp>
#include <coin/filesystem.hpp>
#include <coin/logger.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/wallet.hpp>

using namespace coin;

configuration::configuration()
    : m_network_port_tcp(protocol::default_tcp_port)
    , m_network_tcp_inbound_maximum(network::tcp_inbound_maximum)
    , m_network_tcp_read_maximum(std::numeric_limits<std::size_t>::max())
    , m_network_tcp_write_maximum(std::numeric_limits<std::size_t>::max())
    , m_wallet_transaction_history_maximum(wallet::configuration_interval_history)
    , m_wallet_transaction_fee(constants::default_tx_fee)
    , m_wallet_keypool_size(wallet::configuration_keypool_size)
    , m_wallet_rescan(false)
    , m_database_cache_size(db_env::default_cache_size)
    , m_wallet_deterministic(true)
    , m_db_private(true)
{
    // ...
}

bool configuration::load()
{
    log_info("Configuration is loading from disk.");
    
    boost::property_tree::ptree pt;
    
    try
    {
        std::stringstream ss;
        
        /**
         * Read the json configuration from disk.
         */
        read_json(filesystem::data_path() + "config.dat", pt);
        
        /**
         * Get the version.
         */
        auto file_version = std::stoul(
            pt.get("version", std::to_string(version))
        );
        
        (void)file_version;
        
        log_debug("Configuration read version = " << file_version << ".");
        
        assert(file_version == version);

        /**
         * Get the network.tcp.port
         */
        m_network_port_tcp = std::stoul(
            pt.get("network.tcp.port",
            std::to_string(protocol::default_tcp_port))
        );
        
        log_debug(
            "Configuration read network.tcp.port = " <<
            m_network_port_tcp << "."
        );

        /**
         * Get the network.tcp.inbound.maximum.
         */
        m_network_tcp_inbound_maximum = std::stoul(pt.get(
            "network.tcp.inbound.maximum",
            std::to_string(network::tcp_inbound_maximum))
        );
        
        log_debug(
            "Configuration read network.tcp.inbound.maximum = " <<
            m_network_tcp_inbound_maximum << "."
        );
        
        /**
         * Enforce the minimum network.tcp.inbound.minimum.
         */
        if (m_network_tcp_inbound_maximum < network::tcp_inbound_minimum)
        {
            m_network_tcp_inbound_maximum = network::tcp_inbound_minimum;
        }
        
        /**
         * Get the network.tcp.read.maximum.
         */
        m_network_tcp_read_maximum = std::stoull(pt.get(
            "network.tcp.read.maximum",
            std::to_string(std::numeric_limits<std::size_t>::max()))
        );
        
        log_debug(
            "Configuration read network.tcp.read.maximum = " <<
            m_network_tcp_read_maximum << "."
        );
        
        /**
         * Get the network.tcp.write.maximum.
         */
        m_network_tcp_write_maximum = std::stoull(pt.get(
            "network.tcp.write.maximum",
            std::to_string(std::numeric_limits<std::size_t>::max()))
        );
        
        log_debug(
            "Configuration read network.tcp.write.maximum = " <<
            m_network_tcp_write_maximum << "."
        );
        
        /**
         * Get the wallet.transaction.history.maximum.
         */
        m_wallet_transaction_history_maximum = std::stoull(pt.get(
            "wallet.transaction.history.maximum",
            std::to_string(m_wallet_transaction_history_maximum))
        );
        
        log_debug(
            "Configuration read wallet.transaction.history.maximum = " <<
            m_wallet_transaction_history_maximum << "."
        );
        
        /**
         * Get the wallet.transaction.fee
         */
        m_wallet_transaction_fee = std::stoull(pt.get(
            "wallet.transaction.fee",
            std::to_string(m_wallet_transaction_fee))
        );
        
        /**
         * Check for too high transaction fee.
         */
        if (m_wallet_transaction_fee > (constants::default_tx_fee * 10))
        {
            m_wallet_transaction_fee = constants::default_tx_fee;
        }
        
        /**
         * Check for too low transaction fee.
         */
        if (m_wallet_transaction_fee < (constants::default_tx_fee / 10))
        {
            m_wallet_transaction_fee = constants::default_tx_fee;
        }
        
        log_debug(
            "Configuration read wallet.transaction.fee = " <<
            m_wallet_transaction_fee << "(" <<
            static_cast<double> (m_wallet_transaction_fee) /
            constants::coin << ")."
        );
        
        /**
         * Get the wallet.keypool.size.
         */
        m_wallet_keypool_size = std::stoi(pt.get(
            "wallet.keypool.size",
            std::to_string(m_wallet_keypool_size))
        );
        
        log_debug(
            "Configuration read wallet.keypool.size = " <<
            m_wallet_keypool_size << "."
        );

        /**
         * Get the wallet.rescan.
         */
        m_wallet_rescan = std::stoi(pt.get(
            "wallet.rescan",
            std::to_string(m_wallet_rescan))
        );
        
        log_debug(
            "Configuration read wallet.rescan = " <<
            m_wallet_rescan << "."
        );
        
        /**
         * Get the database.cache_size.
         */
        m_database_cache_size = std::stoi(pt.get(
            "database.cache_size",
            std::to_string(m_database_cache_size))
        );
        
        /**
         * Make sure the database.cache_size stays within a range.
         */
        if (m_database_cache_size < 1 || m_database_cache_size > 32768)
        {
            m_database_cache_size = db_env::default_cache_size;
        }
        
        log_debug(
            "Configuration read database.cache_size = " <<
            m_database_cache_size << "."
        );
        
        /**
         * Get the wallet.deterministic.
         */
        m_wallet_deterministic = std::stoi(pt.get(
            "wallet.deterministic",
            std::to_string(m_wallet_deterministic))
        );
        
        log_debug(
            "Configuration read wallet.deterministic = " <<
            m_wallet_deterministic << "."
        );
        
        /**
         * Get the database.private.
         */
        m_db_private = std::stoi(pt.get(
            "database.private", std::to_string(m_db_private))
        );
        
        log_debug(
            "Configuration read database.private = " << m_db_private << "."
        );
        
        /**
         * Get the rpc.local.whitelist.
         */
        m_rpc_local_whitelist = pt.get("rpc.local.whitelist", "");
        
        log_debug(
            "Configuration read rpc.local.whitelist = " <<
            m_rpc_local_whitelist << "."
        );
    }
    catch (std::exception & e)
    {
        log_error("Configuration failed to load, what = " << e.what() << ".");
    
        return false;
    }
    
    if (m_args.size() > 0)
    {
        /**
         * Iterate the args and override the variables (if found).
         */
    }
    
    return true;
}

bool configuration::save()
{
    log_info("Configuration is saving to disk.");
    
    try
    {
        boost::property_tree::ptree pt;
        
        /**
         * Put the version into property tree.
         */
        pt.put("version", std::to_string(version));
        
        /**
         * Put the network.tcp.port into property tree.
         */
        pt.put("network.tcp.port", std::to_string(m_network_port_tcp));
        
        /**
         * Put the network.tcp.inbound.maximum into property tree.
         */
        pt.put(
            "network.tcp.inbound.maximum",
            std::to_string(m_network_tcp_inbound_maximum)
        );
        
        /**
         * Put the network.tcp.read.maximum into property tree.
         */
        pt.put(
            "network.tcp.read.maximum",
            std::to_string(m_network_tcp_read_maximum)
        );
        
        /**
         * Put the network.tcp.write.maximum into property tree.
         */
        pt.put(
            "network.tcp.write.maximum",
            std::to_string(m_network_tcp_write_maximum)
        );

        /**
         * Put the wallet.transaction.history.maximum into property tree.
         */
        pt.put(
            "wallet.transaction.history.maximum",
            std::to_string(m_wallet_transaction_history_maximum)
        );
        

        /**
         * Put the wallet.transaction.fee into property tree.
         */
        pt.put(
            "wallet.transaction.fee",
            std::to_string(m_wallet_transaction_fee)
        );
        
        /**
         * Put the wallet.keypool.size into property tree.
         */
        pt.put(
            "wallet.keypool.size", std::to_string(m_wallet_keypool_size)
        );
        
        /**
         * Put the wallet.rescan into property tree.
         */
        pt.put(
            "wallet.rescan", std::to_string(m_wallet_rescan)
        );
        
        /**
         * Make sure the database.cache_size stays within a range.
         */
        if (m_database_cache_size < 1 || m_database_cache_size > 32768)
        {
            m_database_cache_size = db_env::default_cache_size;
        }
        
        /**
         * Put the database.cache_size into property tree.
         */
        pt.put(
            "database.cache_size", std::to_string(m_database_cache_size)
        );
        
        /**
         * Put the wallet.deterministic into property tree.
         */
        pt.put(
            "wallet.deterministic", std::to_string(m_wallet_deterministic)
        );
        
        /**
         * Put the database.private into property tree.
         */
        pt.put(
            "database.private", std::to_string(m_db_private)
        );
        
        /**
         * Put the rpc.local.whitelist into property tree.
         */
        pt.put("rpc.local.whitelist", m_rpc_local_whitelist);
        
        /**
         * The std::stringstream.
         */
        std::stringstream ss;
        
        /**
         * Write property tree to json file.
         */
        write_json(ss, pt, true);
        
        /**
         * Open the output file stream.
         */
        std::ofstream ofs(
            filesystem::data_path() + "config.dat"
        );
        
        /**
         * Write the json.
         */
        ofs << ss.str();
        
        /**
         * Flush to disk.
         */
        ofs.flush();
    }
    catch (std::exception & e)
    {
        log_error("Configuration failed to save, what = " << e.what() << ".");
        
        return false;
    }
    
    return true;
}

void configuration::set_args(const std::map<std::string, std::string>  & val)
{
    m_args = val;
}

std::map<std::string, std::string> & configuration::args()
{
    return m_args;
}

void configuration::set_network_port_tcp(const std::uint16_t & val)
{
    m_network_port_tcp = val;
}

const std::uint16_t & configuration::network_port_tcp() const
{
    return m_network_port_tcp;
}

void configuration::set_network_tcp_inbound_maximum(const std::size_t & val)
{
    if (val < network::tcp_inbound_minimum)
    {
        m_network_tcp_inbound_maximum = network::tcp_inbound_minimum;
    }
    else
    {
        m_network_tcp_inbound_maximum = val;
    }
}

const std::size_t & configuration::network_tcp_inbound_maximum() const
{
    return m_network_tcp_inbound_maximum;
}

void configuration::set_network_tcp_read_maximum(const std::size_t & val)
{
    m_network_tcp_read_maximum = val;
}

const std::size_t & configuration::network_tcp_read_maximum() const
{
    return m_network_tcp_read_maximum;
}

void configuration::set_network_tcp_write_maximum(const std::size_t & val)
{
    m_network_tcp_write_maximum = val;
}

const std::size_t & configuration::network_tcp_write_maximum() const
{
    return m_network_tcp_write_maximum;
}

void configuration::set_database_cache_size(const std::uint32_t & val)
{
    m_database_cache_size = val;
}

const std::uint32_t & configuration::database_cache_size() const
{
    return m_database_cache_size;
}

void configuration::set_wallet_deterministic(const bool & val)
{
    m_wallet_deterministic = val;
}

const bool & configuration::wallet_deterministic() const
{
    return m_wallet_deterministic;
}

void configuration::set_db_private(const bool & val)
{
    m_db_private = val;
}

const bool & configuration::db_private() const
{
    return m_db_private;
}

const std::string & configuration::rpc_local_whitelist() const
{
    return m_rpc_local_whitelist;
}
