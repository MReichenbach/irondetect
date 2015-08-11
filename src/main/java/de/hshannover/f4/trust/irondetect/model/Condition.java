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


import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.CONDITION;

import java.util.List;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.gui.ResultLogger;
import de.hshannover.f4.trust.irondetect.gui.ResultLoggerImpl;
import de.hshannover.f4.trust.irondetect.util.BooleanOperator;
import de.hshannover.f4.trust.irondetect.util.Pair;

/**
 * @author jvieweg
 *
 */
public class Condition extends Evaluable implements PolicyData {
	
	private static Logger logger = Logger.getLogger(Condition.class);
        private ResultLogger rlogger = ResultLoggerImpl.getInstance();

	private List<Pair<ConditionElement, BooleanOperator>> conditionSet;
	
	private Rule parent;

	
	
	/**
	 * @return the conditionSet
	 */
	public List<Pair<ConditionElement, BooleanOperator>> getConditionSet() {
		return conditionSet;
	}

	/**
	 * @param conditionSet the conditionSet to set
	 */
	public void setConditionSet(List<Pair<ConditionElement, BooleanOperator>> conditionSet) {
		this.conditionSet = conditionSet;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder condSetStr = new StringBuilder("conditionSet=");
		if(conditionSet != null) {
			for (Pair<ConditionElement, BooleanOperator> p : conditionSet) {
			condSetStr.append(p.toString());
			}
		}
		return "Condition [" + condSetStr + ", "
				+ super.toString() + "]";
	}

	@Override
	public boolean evaluate(String device) {
		logger.debug("evaluating condition " + this.getId());
		for (Pair<ConditionElement, BooleanOperator> p : this.conditionSet) {
			p.getFirstElement().setParent(this.parent);
		}
		boolean result = evaluateConditionSet(device);
		logger.debug("condition " + super.id + " evaluation returned " + result);
		rlogger.reportResultsToLogger(device, super.id, CONDITION, result);
		return result;

	}
	
	private boolean evaluateConditionSet(String device) {
		boolean result = false;
		if(getConditionSet().size() < 2) {
			return getConditionSet().get(0).getFirstElement().evaluate(device);
		}
		BooleanOperator op = getConditionSet().get(1).getSecondElement();
		switch (op) {
		case AND:
			for (int i = 0; i < getConditionSet().size(); i++) {
				result = getConditionSet().get(i).getFirstElement().evaluate(device);
				if(!result){
					return result;
				}
			}
			break;
		case OR:
			for (int i = 0; i < getConditionSet().size(); i++) {
				result = getConditionSet().get(i).getFirstElement().evaluate(device);
				if(result){
					return result;
				}
			}
			break;
		default:
			logger.error("Only AND/OR supported at this time!");
			break;
		}
		return result;
	}
	
	/**
	 * @param parent the parent rule to set
	 */
	public void setParent(Rule parent) {
		this.parent = parent;
	}

}
