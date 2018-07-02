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
#include <mutex>

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/version_bits.hpp>

using namespace coin;

version_bits::version_bits()
{
    /**
     * Set the period.
     */
    m_parameters.period = period;
    
    /**
     * Set the threshold.
     */
    m_parameters.threshold = threshold;

    /**
     * deployment_type_testdummy
     * start_time = January 1, 2008
     * timeout = December 31, 2008
     */
    m_parameters.deployments[deployment_type_testdummy].bit =
        deployment_bit_testdummy
    ;
    m_parameters.deployments[deployment_type_testdummy].start_time = 1199145601;
    m_parameters.deployments[deployment_type_testdummy].timeout = 1230767999;

    /**
     * deployment_type_csv
     * start_time = May 1st, 2016
     * timeout = May 1st, 2017
     */
    m_parameters.deployments[deployment_type_csv].bit = deployment_bit_csv;
    m_parameters.deployments[deployment_type_csv].start_time = 1462060800;
    m_parameters.deployments[deployment_type_csv].timeout = 1493596800;

    /**
     * deployment_type_segwit
     * start_time = November 15th, 2016.
     * timeout = November 15th, 2017.
     */
    m_parameters.deployments[deployment_type_segwit].bit =
        deployment_bit_segwit
    ;
    m_parameters.deployments[deployment_type_segwit].start_time = 1479168000;
    m_parameters.deployments[deployment_type_segwit].timeout = 1510704000;
    
    /**
     * deployment_type_segwit
     * start_time = June 1st, 2017.
     * timeout = November 15th, 2017.
     */
    m_parameters.deployments[deployment_type_segwit2x].bit =
        deployment_bit_segwit2x
    ;
    m_parameters.deployments[deployment_type_segwit2x].start_time = 1496275200;
    m_parameters.deployments[deployment_type_segwit2x].timeout = 1510704000;
}

version_bits & version_bits::instance()
{
    static version_bits g_version_bits;
    
    static std::recursive_mutex g_recursive_mutex;
    
    std::lock_guard<std::recursive_mutex> l1(g_recursive_mutex);
    
    return g_version_bits;
}

std::uint32_t version_bits::block_version_compute(
    const block_index * block_index_previous, const parameters_t & params
    )
{
    std::uint32_t ret = top_bits;
    
    for (auto i = 0; i < params.deployments.size(); i++)
    {
        version_bits::threshold_state_t state = version_bits_state(
            block_index_previous, params, static_cast<deployment_t> (i),
            m_threshold_condition_cache
        );
        
        if (state == threshold_locked_in || state == threshold_started)
        {
            ret |= version_bits_mask(params, static_cast<deployment_t> (i));
        }
    }

    return ret;
}

bool version_bits::block_version_has_bit_set(
    const std::uint32_t & version, const deployment_bit_t & bit
    )
{
    auto has_top_bits = (
        (version & top_mask) == top_bits
    );
    auto has_bit = (
        (version & (static_cast<std::uint32_t> (1)) << bit)
    );
    
    return (has_top_bits && has_bit) != 0;
}

std::vector< std::map<std::string, std::string> >
    version_bits::deployment_proposals_from_versions(
    const std::vector<std::uint32_t> & versions
    )
{
    std::vector< std::map<std::string, std::string> > ret;
    
    /**
     * testdummy
     */
    auto count_deployment_bit_testdummy = 0;
    
    /**
     * csv
     */
    auto count_deployment_bit_csv = 0;
    
    /**
     * segwit
     */
    auto count_deployment_bit_segwit = 0;
    
    /**
     * segwit2x
     */
    auto count_deployment_bit_segwit2x = 0;
    
    for (auto & i : versions)
    {
        /**
         * testdummy
         */
        if (
            block_version_has_bit_set(i,
            deployment_bit_testdummy) == true
            )
        {
            count_deployment_bit_testdummy++;
        }
        
        /**
         * csv
         */
        if (
            block_version_has_bit_set(i,
            deployment_bit_csv) == true
            )
        {
            count_deployment_bit_csv++;
        }
        
        /**
         * segwit
         */
        if (
            block_version_has_bit_set(i,
            deployment_bit_segwit) == true
            )
        {
            count_deployment_bit_segwit++;
        }
        
        /**
         * segwit
         */
        if (
            block_version_has_bit_set(i,
            deployment_bit_segwit2x) == true
            )
        {
            count_deployment_bit_segwit2x++;
        }
    }
    
    if (count_deployment_bit_testdummy > 0)
    {
        std::map<std::string, std::string> deployment;
        
        deployment["bip9.deployment.type"] = "testdummy";
        deployment["bip9.blocks"] = std::to_string(
            count_deployment_bit_testdummy
        );
        deployment["bip9.blocks.percentage"] = std::to_string(
            (static_cast<double> (count_deployment_bit_testdummy) /
            versions.size()) * 100.0f
        );
        
        ret.push_back(deployment);
    }
    
    if (count_deployment_bit_csv > 0)
    {
        std::map<std::string, std::string> deployment;
        
        deployment["bip9.deployment.type"] = "csv";
        deployment["bip9.blocks"] = std::to_string(
            count_deployment_bit_csv
        );
        deployment["bip9.blocks.percentage"] = std::to_string(
            (static_cast<double> (count_deployment_bit_csv) /
            versions.size()) * 100.0f
        );
        
        ret.push_back(deployment);
    }
    
    if (count_deployment_bit_segwit > 0)
    {
        std::map<std::string, std::string> deployment;
        
        deployment["bip9.deployment.type"] = "segwit";
        deployment["bip9.blocks"] = std::to_string(
            count_deployment_bit_segwit
        );
        deployment["bip9.blocks.percentage"] = std::to_string(
            (static_cast<double> (count_deployment_bit_segwit) /
            versions.size()) * 100.0f
        );
        
        ret.push_back(deployment);
    }
    
    if (count_deployment_bit_segwit2x > 0)
    {
        std::map<std::string, std::string> deployment;
        
        deployment["bip9.deployment.type"] = "segwit2x";
        deployment["bip9.blocks"] = std::to_string(
            count_deployment_bit_segwit
        );
        deployment["bip9.blocks.percentage"] = std::to_string(
            (static_cast<double> (count_deployment_bit_segwit) /
            versions.size()) * 100.0f
        );
        
        ret.push_back(deployment);
    }
    
    return ret;
}

void version_bits::clear_threshold_condition_cache()
{
    for (auto i = 0; i < deployment_type_maximum_deployments; i++)
    {
        m_threshold_condition_cache[i].clear();
    }
}

const version_bits::parameters_t & version_bits::parameters() const
{
    return m_parameters;
}

std::map<const block_index *, version_bits::threshold_state_t> *
    version_bits::threshold_condition_cache()
{
    return m_threshold_condition_cache;
}

version_bits::threshold_state_t version_bits::version_bits_state(
    const block_index * block_index_previous, const parameters_t & params,
    const deployment_t & deployment,
    std::map<const block_index *, threshold_state_t>
    cache[deployment_type_maximum_deployments]
    )
{
    return
        condition_checker(deployment).get_state_for(
            block_index_previous, params, cache[deployment]
        )
    ;
}

version_bits::statistics_t version_bits::version_bits_statistics(
    const block_index * block_index_previous,
    const parameters_t & params, const deployment_t & deployment
    )
{
    return
        condition_checker(deployment).get_state_statistics_for(
        block_index_previous, params)
    ;
}

std::int32_t version_bits::version_bits_state_since_height(
    const block_index * block_index_previous, const parameters_t & params,
    const deployment_t & deployment,
    std::map<const block_index *, threshold_state_t>
    cache[deployment_type_maximum_deployments]
    )
{
    return
        condition_checker(deployment).get_state_since_height_for(
        block_index_previous, params, cache[deployment])
    ;
}

std::uint32_t version_bits::version_bits_mask(
    const parameters_t & params, const deployment_t & deployment
    )
{
    /**
     * Get the deployment bit.
     */
    auto bit = params.deployments[deployment].bit;
    
    return condition_checker(deployment).mask(bit);
}

std::string version_bits::deployment_type_to_string(const deployment_t & type)
{
    std::string ret;
    
    switch (type)
    {
        case deployment_type_testdummy:
        {
            ret = "testdummy";
        }
        break;
        case deployment_type_csv:
        {
            ret = "csv";
        }
        break;
        case deployment_type_segwit:
        {
            ret = "segwit";
        }
        break;
        case deployment_type_segwit2x:
        {
            ret = "segwit2x";
        }
        break;
        default:
        {
            ret = "unknown";
        }
        break;
    }
    
    return ret;
}

version_bits::condition_checker::condition_checker(
    const version_bits::deployment_t & deployment
    )
    : m_deployment(deployment)
{
    // ...
}

version_bits::threshold_state_t
    version_bits::condition_checker_base::get_state_for(
    const block_index * block_index_previous,
    const parameters_t & params,
    std::map<const block_index *, threshold_state_t> & cache
    ) const
{
    const std::uint32_t period = get_period(params);
    const std::uint32_t threshold = get_threshold(params);
    const std::time_t time_start_time = get_time_begin(params);
    const std::time_t time_timeout = get_time_end(params);
    
    if (block_index_previous != nullptr)
    {
        block_index_previous =
            block_index_previous->get_ancestor(block_index_previous->height() -
            ((block_index_previous->height() + 1) % period))
        ;
    }
    
    std::vector<const block_index *> to_compute;
    
    /**
     * Go backwards in intervals of period to find a block_index that is known.
     */
    while (cache.count(block_index_previous) == 0)
    {
        if (block_index_previous == nullptr)
        {
            /**
             * The genesis block is by default defined.
             */
            
            cache[block_index_previous] = threshold_defined;
            
            break;
        }
        
        if (
            const_cast<block_index *> (
            block_index_previous)->get_median_time_past() < time_start_time
            )
        {
            cache[block_index_previous] = threshold_defined;
            
            break;
        }
        
        to_compute.push_back(block_index_previous);
        
        block_index_previous = block_index_previous->get_ancestor(
            block_index_previous->height() - period
        );
    }
    
    assert(cache.count(block_index_previous));
    
    auto state = cache[block_index_previous];

    /**
     * Go forward and calculate descendant states.
     */
    while (to_compute.size() > 0)
    {
        auto state_next = state;
        
        block_index_previous = to_compute.back();
        
        to_compute.pop_back();

        switch (state)
        {
            case threshold_defined:
            {
                if (
                    const_cast<block_index *> (block_index_previous
                    )->get_median_time_past() >= time_timeout
                    )
                {
                    state_next = threshold_failed;
                }
                else if (
                    const_cast<block_index *> (
                    block_index_previous)->get_median_time_past() >=
                    time_start_time
                    )
                {
                    state_next = threshold_started;
                }
            }
            break;
            case threshold_started:
            {
                if (
                    const_cast<block_index *> (
                    block_index_previous)->get_median_time_past() >=
                    time_timeout
                    )
                {
                    state_next = threshold_failed;
                }
                else
                {
                    const block_index * block_index_count =
                        block_index_previous
                    ;
                    
                    auto count = 0;
                    
                    for (auto i = 0; i < period; i++)
                    {
                        if (condition(block_index_count, params))
                        {
                            count++;
                        }
                        
                        block_index_count =
                            block_index_count->block_index_previous()
                        ;
                    }

                    if (count >= threshold)
                    {
                        state_next = threshold_locked_in;
                    }
                }
            }
            break;
            case threshold_locked_in:
            {
                state_next = threshold_active;
            }
            break;
            case threshold_failed:
            case threshold_active:
            {
                // ...
            }
            break;
        }
        
        cache[block_index_previous] = state = state_next;
    }

    return state;
}

version_bits::statistics_t
    version_bits::condition_checker_base::get_state_statistics_for(
        const block_index * index, const parameters_t & params
    ) const
{
    version_bits::statistics_t stats;

    stats.period = get_period(params);
    stats.threshold = get_threshold(params);

    if (index == nullptr)
    {
        return stats;
    }

    const auto * block_index_end_of_previous_period =
        index->get_ancestor(index->height() -
        ((index->height() + 1) % stats.period))
    ;
    
    stats.elapsed =
        index->height() - block_index_end_of_previous_period->height()
    ;

    auto count = 0;
    
    const auto * index_current = index;
    
    while (
        block_index_end_of_previous_period->height() != index_current->height()
        )
    {
        if (condition(index_current, params))
        {
            count++;
        }
        
        index_current = index_current->block_index_previous();
    }

    stats.count = count;
    
    stats.possible =
        (stats.period - stats.threshold) >= (stats.elapsed - count)
    ;

    return stats;
}

std::int32_t version_bits::condition_checker_base::get_state_since_height_for(
    const block_index * block_index_previous, const parameters_t & params,
    std::map<const block_index *, threshold_state_t> & cache) const
{
    const auto state_initial =
        get_state_for(block_index_previous, params, cache)
    ;

    if (state_initial == threshold_defined)
    {
        return 0;
    }

    const auto period = get_period(params);

    block_index_previous =
        block_index_previous->get_ancestor(block_index_previous->height() -
        ((block_index_previous->height() + 1) % period))
    ;

    const auto * previous_period_parent =
        block_index_previous->get_ancestor(
        block_index_previous->height() - period)
    ;

    while (
        previous_period_parent != nullptr &&
        get_state_for(previous_period_parent, params, cache) == state_initial)
    {
        block_index_previous = previous_period_parent;
        
        previous_period_parent =
            block_index_previous->get_ancestor(
            block_index_previous->height() - period)
        ;
    }

    return block_index_previous->height() + 1;
}

std::uint32_t version_bits::condition_checker::mask(
    const deployment_bit_t & bit
    ) const
{
    return (static_cast<std::uint32_t> (1)) << bit;
}

bool version_bits::condition_checker::condition(
    const block_index * pindex, const parameters_t & params
    ) const
{
    const auto & block_header = pindex->get_block_header().header();
    
    /**
     * Get the deployment bit.
     */
    auto bit = params.deployments[m_deployment].bit;
    
    return
        (((block_header.version & top_mask) == top_bits) &&
        (block_header.version & mask(bit)) != 0)
    ;
}

std::time_t version_bits::condition_checker::get_time_begin(
    const parameters_t & params
    ) const
{
    auto deployment = params.deployments[m_deployment];

    return deployment.start_time;
}

std::time_t version_bits::condition_checker::get_time_end(
    const parameters_t & params
    ) const
{
    auto deployment = params.deployments[m_deployment];
    
    return deployment.timeout;
}

std::uint32_t version_bits::condition_checker::get_period(
    const parameters_t & params
    ) const
{
    return params.period;
}

std::uint32_t version_bits::condition_checker::get_threshold(
    const parameters_t & params
    ) const
{
    return params.threshold;
}
