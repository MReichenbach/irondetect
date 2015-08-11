/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de/
 * 
 * This file is part of irondetect, version 0.0.8,
 * implemented by the Trust@HsH research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2010 - 2015 Trust@HsH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
/**
 * 
 */
package de.hshannover.f4.trust.irondetect.model;


import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.RULE;

import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.engine.Processor;
import de.hshannover.f4.trust.irondetect.gui.ResultLogger;
import de.hshannover.f4.trust.irondetect.gui.ResultLoggerImpl;

/**
 * @author jvieweg
 *
 */
public class Rule implements PolicyData {
	
	private Logger logger = Logger.getLogger(this.getClass());
        private ResultLogger rlogger = ResultLoggerImpl.getInstance();
	
	private Condition condition;
	private List<Action> actions;
	private String id;
	private Set<String> featureIds;

	
	/**
	 * checks the condition, if it is true all actions will be performed
	 */
	public void evaluate(String device) {
		
		logger.info("checking rule " + getId());
		this.condition.setParent(this);
		boolean result = this.condition.evaluate(device);
		logger.info("rule " + getId() + " result was " + result);
		rlogger.reportResultsToLogger(device, this.id, RULE, result);
		// we only perform actions when in testing mode
		if(result && Processor.getInstance().isTesting()) {
			for (Action a : actions) {
				a.perform(device);
			}
		}
	}
	
	/**
	 * @return the condition
	 */
	public Condition getCondition() {
		return condition;
	}

	/**
	 * @param condition the condition to set
	 */
	public void setCondition(Condition condition) {
		this.condition = condition;
	}

	/**
	 * @return the actions
	 */
	public List<Action> getActions() {
		return actions;
	}

	/**
	 * @param actions the actions to set
	 */
	public void setActions(List<Action> actions) {
		this.actions = actions;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder actionStr = new StringBuilder("actions=");
		if(actions != null) {
			for (Action a : actions) {
				actionStr.append(a.toString());
			}
		}
		return "Rule [condition=" + (condition != null ? condition : " ") + ", " + actionStr.toString()
				+ ", " + super.toString() + "]";
	}

	/**
	 * 
	 * @param featureIds
	 * @return true if one of the given featureIds is used by this rule
	 */
	public boolean contains(Set<String> changedfeatureIds) {
		assert this.featureIds != null : "Feature set saved in rule shouldn't be null!";
		for (String id : this.featureIds) {
			if (id.startsWith(Policy.COUNT_KEY)) {
				id = id.substring(1);
			}
			if (changedfeatureIds.contains(id)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * @param featureIds the featureIds to set
	 */
	public void setFeatureIds(Set<String> featureIds) {
		this.featureIds = featureIds;
	}

}
