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


import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.ANOMALY;

import java.util.List;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.engine.Processor;
import de.hshannover.f4.trust.irondetect.gui.ResultLogger;
import de.hshannover.f4.trust.irondetect.gui.ResultLoggerImpl;
import de.hshannover.f4.trust.irondetect.util.BooleanOperator;
import de.hshannover.f4.trust.irondetect.util.Pair;

/**
 *
 * If training, no triggers are created.
 *
 * @author jvieweg
 * @author ib
 *
 */
public class Anomaly extends ConditionElement {

    private Logger logger = Logger.getLogger(this.getClass());
    private ResultLogger rlogger = ResultLoggerImpl.getInstance();
    private List<Pair<HintExpression, BooleanOperator>> hintSet;

    /**
     * @return the hintSet
     */
    public List<Pair<HintExpression, BooleanOperator>> getHintSet() {
        return hintSet;
    }

    /**
     * @param hintSet the hintSet to set
     */
    public void setHintSet(List<Pair<HintExpression, BooleanOperator>> hintSet) {
        this.hintSet = hintSet;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder hSetStr = new StringBuilder("hintSet=");
        for (Pair<HintExpression, BooleanOperator> p : hintSet) {
            hSetStr.append(p.toString());
        }
        return "Anomaly [" + hSetStr.toString() + ", "
                + super.toString() + "]";
    }

    @Override
    public boolean evaluate(String device) {

        logger.info("----------------Evaluating anomaly " + this.id + " for device " + device + "---------------------");

        /**
         * Only create triggers in testing mode
         */
        if (Processor.getInstance().isTesting()) {
            super.checkSlidingCtx(device);
        }

        long sTime = System.currentTimeMillis();

        for (Pair<HintExpression, BooleanOperator> p : hintSet) {
            Hint hint = p.getFirstElement().getHintValuePair().getFirstElement();
            List<String> featureIdSet = hint.getFeatureIds();
            List<Feature> fVals = getFeatureValues(device, featureIdSet);

            //logger.warn("#### " + fVals.size());

            if (fVals.isEmpty()) {
                logger.warn("--------------------Anomaly " + this.id +
                        " no features found for Hint " + hint.getId() + " --------------------");
                //rlogger.reportResultsToLogger(device, id, Anomaly.class.getSimpleName(), false);
                //continue;
            }

//                        // FIXME this seems to be bullshit. we add features to the same container in the same hint
//			for (String fId : p.getFirstElement().getHintValuePair().getFirstElement().getFeatureIds()) {
//				for (Feature feature : fVals) {
//					if (fId.equals(feature.getQualifiedIdWithoutInstance()) && p.getFirstElement().getHintValuePair().getFirstElement().getFeatureSet() != null ) {
//						logger.trace("found " + feature.getQualifiedIdWithoutInstance() + ", adding it to feature set...");
//						p.getFirstElement().getHintValuePair().getFirstElement().getFeatureSet().add(feature);
//					}
//				}
//			}

            // set effective featureset in hint
            hint.setFeatureSet(fVals);
        }

        // evaluate all hints
        boolean result = evaluateHintSet(device);
        long eTime = System.currentTimeMillis();
        logger.info("--------------------Anomaly " + this.id + " eval finished with " + result + "--------------------");
		rlogger.reportResultsToLogger(device, id, ANOMALY, result);
        super.printTimedResult(getClass(), result, eTime - sTime);
        return result;

    }

    private boolean evaluateHintSet(String device) {
        boolean result = false;
        HintExpression h;

        if (getHintSet().size() < 2) {
            h = this.hintSet.get(0).getFirstElement();
            h.setCurrentAnomaly(this);
            return h.evaluate(device);
        }

        BooleanOperator op = getHintSet().get(1).getSecondElement();
        switch (op) {
            case AND:
                for (int i = 0; i < getHintSet().size(); i++) {
                    h = getHintSet().get(i).getFirstElement();
                    h.setCurrentAnomaly(this);
                    result = h.evaluate(device);
                    if (!result) {
                        return result;
                    }
                }
                break;
            case OR:
                for (int i = 0; i < getHintSet().size(); i++) {
                    h = getHintSet().get(i).getFirstElement();
                    h.setCurrentAnomaly(this);
                    result = h.evaluate(device);
                    if (result) {
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
}
