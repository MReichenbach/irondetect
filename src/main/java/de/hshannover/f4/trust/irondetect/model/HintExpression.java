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
package de.hshannover.f4.trust.irondetect.model;


import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.HINT;
import de.hshannover.f4.trust.irondetect.gui.ResultLogger;
import de.hshannover.f4.trust.irondetect.gui.ResultLoggerImpl;
import de.hshannover.f4.trust.irondetect.util.ComparisonOperator;
import de.hshannover.f4.trust.irondetect.util.Pair;

/**
 * @author rosso
 * @author ib
 *
 */
public class HintExpression extends Evaluable {
	/**
	 * 
	 */
	private Pair<Hint, Pair<ComparisonOperator, String>> hintValPair;
	
	private Anomaly currentAnomaly;
	
	private ResultLogger rlogger = ResultLoggerImpl.getInstance();

	public Anomaly getCurrentAnomaly() {
		return currentAnomaly;
	}

	public void setCurrentAnomaly(Anomaly currentAnomaly) {
		this.currentAnomaly = currentAnomaly;
	}

	/**
	 * @param hintValPair
	 */
	public void setHintValuePair(Pair<Hint, Pair< ComparisonOperator, String>> hintValPair) {
		this.hintValPair = hintValPair;
	}
	
	/**
	 * @return
	 */
	public Pair<Hint, Pair<ComparisonOperator, String>> getHintValuePair() {
		return this.hintValPair;
	}

	@Override
	public boolean evaluate(String device) {
		Hint hint = hintValPair.getFirstElement();
		double actual = hint.evaluate(device, getCurrentAnomaly());
		boolean result = evaluateCompOpOnNumber(hintValPair.getSecondElement().getFirstElement(), actual,
				Double.parseDouble(hintValPair.getSecondElement().getSecondElement()));

		rlogger.reportResultsToLogger(device, hint.getId(), HINT, result);

		return result;

	}

}
