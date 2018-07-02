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

#ifndef COIN_VERSION_BITS_HPP
#define COIN_VERSION_BITS_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <ctime>
#include <map>
#if (defined __ANDROID__)
#include <coin/android.hpp>
#else
#include <string>
#endif // __ANDROID__
#include <vector>

namespace coin {
    
    class block_index;
    
    /**
     * Implements (BIP9) version bits.
     */
    class version_bits
    {
        public:

            /**
             * 14 Days with 10 minute blocks.
             */
            enum { period = 2016 };
        
            /**
             * 80% of period.
             */
            enum { threshold = 1612 };

            /**
             * The statistics.
             */
            typedef struct statistics_s
            {
                std::uint32_t period;
                std::uint32_t threshold;
                std::uint32_t elapsed;
                std::uint32_t count;
                bool possible;
            } statistics_t;
        
            /**
             * The deployment bits.
             */
            typedef enum deployment_bit_s
            {
                deployment_bit_csv = 0,
                deployment_bit_segwit = 1,
                deployment_bit_segwit2x = 4,
                deployment_bit_testdummy = 28,
            } deployment_bit_t;
        
            /**
             * A consensus rule deployment proposal.
             */
            typedef struct deployment_proposal_s
            {
                /**
                 * The bit.
                 */
                deployment_bit_t bit;
                
                /**
                 * The start time.
                 */
                std::time_t start_time;

                /**
                 * The timeout.
                 */
                std::time_t timeout;
                
            } deployment_proposal_t;

            /**
             * The deployment types.
             */
            typedef enum deployment_s
            {
                deployment_type_testdummy,
                deployment_type_csv,
                deployment_type_segwit,
                deployment_type_segwit2x,
                
                /**
                 * New deployments go here or can replace an already active
                 * deployment.
                 */
                
                deployment_type_maximum_deployments
            } deployment_t;
        
            /**
             * The bits to set for all BIP9 blocks.
             */
            enum { top_mask = 0xE0000000UL };
        
            /**
             * Bitmask to check if BIP9 top mask is in use.
             */
            enum { top_bits = 0x20000000UL };

            /**
             * (Threshold) States
             * With each block and soft fork, we associate a deployment state.
             * The possible states are: DEFINED is the first state that each
             * soft fork starts out as. The genesis block is by definition in
             * this state for each deployment. STARTED for blocks past the
             * starttime. LOCKED_IN for one retarget period after the first
             * retarget period with STARTED blocks of which at least threshold
             * have the associated bit set in version. ACTIVE for all blocks
             * after the LOCKED_IN retarget period. FAILED for one retarget
             * period past the timeout time, if LOCKED_IN was not reached.
             */
            typedef enum threshold_state_s
            {
                threshold_defined,
                threshold_started,
                threshold_locked_in,
                threshold_active,
                threshold_failed,
            } threshold_state_t;

            /**
             * The parameters.
             */
            typedef struct parameters_s
            {
                std::uint32_t period;
                std::uint32_t threshold;
                std::array<
                    deployment_proposal_t,
                    deployment_type_maximum_deployments>
                deployments;
            } parameters_t;
        
            /**
             * Constructor
             */
            version_bits();
        
            /**
             * The singleton accessor.
             */
            static version_bits & instance();
        
            /**
             * Computes a block version given the deployments.
             * @param
             * @param
             */
            std::uint32_t block_version_compute(
                const block_index * block_index_previous,
                const parameters_t & params
            );
        
            /**
             * Checks a block version to see if the given bit is set.
             * @param version The block version.
             * @param bit The bit.
             */
            bool block_version_has_bit_set(
                const std::uint32_t & version, const deployment_bit_t & bit
            );
        
            /**
             * Compiles the deployment proposals given an array of block
             * header versions.
             * @param versions An array of block header versions.
             */
            std::vector< std::map<std::string, std::string> >
                deployment_proposals_from_versions(
                const std::vector<std::uint32_t> & versions
            );
        
            /**
             * Clears the threshold condition cache.
             */
            void clear_threshold_condition_cache();
        
            /**
             * The parameters.
             */
            const parameters_t & parameters() const;
        
            /**
             * The threshold condition cache.
             */
            std::map<const block_index *, threshold_state_t>
                * threshold_condition_cache()
            ;
        
            /**
             * Gets the version bit state given block_index.
             * @param block_index_previous The block_index.
             * @param params The parameters_t.
             * @param deployment The deployment_t.
             * @param cache The cache.
             */
            threshold_state_t version_bits_state(
                const block_index * block_index_previous,
                const parameters_t & params, const deployment_t & deployment,
                std::map<const block_index *, threshold_state_t>
                cache[deployment_type_maximum_deployments]
            );
        
            /**
             * Gets statistics given block_index.
             * @param block_index_previous The block_index.
             * @param params The parameters_t.
             * @param deployment The deployment_t.
             */
            statistics_t version_bits_statistics(
                const block_index * block_index_previous,
                const parameters_t & params, const deployment_t & deployment
            );
        
            /**
             * Gets the state since height.
             * @param block_index_previous The block_index.
             * @param params The parameters_t.
             * @param deployment The deployment_t.
             * @param cache The cache.
             */
            std::int32_t version_bits_state_since_height(
                const block_index * block_index_previous,
                const parameters_t & params, const deployment_t & deployment,
                std::map<const block_index *, threshold_state_t>
                cache[deployment_type_maximum_deployments]
            );

            /**
             * Gets the mask given parameters and deployment.
             * @param params The parameters_t.
             * @param deployment The deployment_t.
             */
            std::uint32_t version_bits_mask(
                const parameters_t & params, const deployment_t & deployment
            );
        
            /**
             * Converts a deployment_t to it's string (name) representation.
             * @param type The deployment_t.
             */
            std::string deployment_type_to_string(
                const deployment_t & type
            );

            /**
             * Condition checker base class.
             */
            class condition_checker_base
            {
                public:
                
                    /**
                     * Gets the state for the given block_index (previous) and
                     * parameters and cache.
                     * @param block_index_previous The block_index (previous).
                     * @param params The parameters_t.
                     */
                    threshold_state_t get_state_for(
                        const block_index * block_index_previous,
                        const parameters_t & params,
                        std::map<const block_index *, threshold_state_t> & cache
                    ) const;
            
                    /**
                     * Gets the state statistics for the block_index and
                     * parameters.
                     * @param index The block_index.
                     * @param params The parameters_t.
                     */
                    statistics_t get_state_statistics_for(
                        const block_index * index, const parameters_t & params
                    ) const;
                
                    /**
                     * Gets the state since height of given block_index
                     * (previous) and parameters and cache.
                     * @param block_index_previous The block_index (previous).
                     * @param params The parameters_t.
                     */
                    std::int32_t get_state_since_height_for(
                        const block_index * block_index_previous,
                        const parameters_t & params,
                        std::map<const block_index *,
                        threshold_state_t> & cache) const
                    ;
                    
                private:
                
                    // ...
                
                protected:

                    /**
                     * Checks the condition against given block_index and
                     * parameters.
                     * @param index The block_index.
                     * @param params The parameters_t.
                     */
                    virtual bool condition(
                        const block_index * index, const parameters_t & params
                    ) const = 0;
                
                    /**
                     * Gets the time_begin (start_time) given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::time_t get_time_begin(
                        const parameters_t & params
                    ) const = 0;
                
                    /**
                     * Gets the time_end (timeout) given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::time_t get_time_end(
                        const parameters_t & params
                    ) const = 0;
                
                    /**
                     * Gets the period given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::uint32_t get_period(
                        const parameters_t & params
                    ) const = 0;
                
                    /**
                     * Gets the threshold given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::uint32_t get_threshold(
                        const parameters_t & params
                    ) const = 0;
            };

            /**
             * Implements a condition checker.
             */
            class condition_checker : public condition_checker_base
            {
                public:
                
                    /**
                     * Constructor
                     * @param deployment The deployment_t.
                     */
                    condition_checker(const deployment_t & deployment);
            
                    /**
                     * Calculates the mask of the given bit.
                     * @param bit The deployment_bit_t.
                     */
                    std::uint32_t mask(const deployment_bit_t & bit) const;
                
                private:
                
                    /**
                     * The deployment.
                     */
                    deployment_t m_deployment;
            
                protected:
                
                    /**
                     * Checks the condition against given block_index and
                     * parameters.
                     * @param index The block_index.
                     * @param params The parameters_t.
                     */
                    virtual bool condition(
                        const block_index * index, const parameters_t & params
                    ) const;
                
                    /**
                     * Gets the time_begin (start_time) given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::time_t get_time_begin(
                        const parameters_t & params
                    ) const;
                
                    /**
                     * Gets the time_end (timeout) given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::time_t get_time_end(
                        const parameters_t & params
                    ) const;
                
                    /**
                     * Gets the period given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::uint32_t get_period(
                        const parameters_t & params
                    ) const;
                
                    /**
                     * Gets the threshold given parameters.
                     * @param params The parameters_t.
                     */
                    virtual std::uint32_t get_threshold(
                        const parameters_t & params
                    ) const;
            };
        
        private:
    
            /**
             * The parameters.
             */
            parameters_t m_parameters;
    
            /**
             * The threshold condition cache.
             */
            std::map<const block_index *, threshold_state_t>
                m_threshold_condition_cache[deployment_type_maximum_deployments]
            ;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_VERSION_BITS_HPP
