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


import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.SIGNATURE;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.engine.Processor;
import de.hshannover.f4.trust.irondetect.gui.ResultLogger;
import de.hshannover.f4.trust.irondetect.gui.ResultLoggerImpl;
import de.hshannover.f4.trust.irondetect.util.BooleanOperator;
import de.hshannover.f4.trust.irondetect.util.ComparisonOperator;
import de.hshannover.f4.trust.irondetect.util.Pair;

/**
 * @author jvieweg
 *
 */
public class Signature extends ConditionElement {

    private Logger logger = Logger.getLogger(this.getClass());
    private ResultLogger rlogger = ResultLoggerImpl.getInstance();
    private List<Pair<FeatureExpression, BooleanOperator>> featureSet;

    /**
     * @return the featureSet
     */
    public List<Pair<FeatureExpression, BooleanOperator>> getFeatureSet() {
        return featureSet;
    }

    /**
     * @param featureSet the featureSet to set
     */
    public void setFeatureSet(List<Pair<FeatureExpression, BooleanOperator>> featureSet) {
        this.featureSet = featureSet;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder sigStr = new StringBuilder("featureSet=");
        for (Pair<FeatureExpression, BooleanOperator> p : featureSet) {
            sigStr.append(p.toString());
        }
        return "Signature [" + sigStr.toString() + ", " + super.toString() + "]";
    }

    @Override
    public boolean evaluate(String device) {

        /**
         * Evaluate signatures only in testing mode
         */
        if (!Processor.getInstance().isTesting()) {
            return true;
        }
        logger.debug("----------------Evaluating signature " + this.id + " for device " + device + "---------------------");

        super.checkSlidingCtx(device);
        logger.trace("preparing feature ids");


        //time measurement
        long sTime = System.currentTimeMillis();
        long eTime = 0;

        //final result field
        boolean result = false;

        //the full set of feature expressions (including instance copies)
        ArrayList<FeatureExpression> featureExpr = new ArrayList<FeatureExpression>();

        //derived id set
        List<String> fIds = new ArrayList<String>();

        //derived id count set
        List<String> fIdsCount = new ArrayList<String>();

        //blacklisted fIDs
        List<String> blacklisted = new ArrayList<String>();

        //copy all fIds parsed out of the policy into the id set
        for (Pair<FeatureExpression, BooleanOperator> p : this.featureSet) {

            //distinguish between features that shall be counted and normal features
            if (p.getFirstElement().getFeatureId().contains(Policy.COUNT_KEY)) {
                logger.trace("-->found count " + p.getFirstElement().getFeatureId().substring(1));
                //add count ids to the count set
                fIdsCount.add(p.getFirstElement().getFeatureId().substring(1));
            } else {
                logger.trace("->found id " + p.getFirstElement().getFeatureId());
                //normal features
                fIds.add(p.getFirstElement().getFeatureId());
            }
        }

        //receive actual features from the featureBase, if there are instances-
        //this should be larger than the fId-set which was used to query the featureBase
        List<Feature> fVals = getFeatureValues(device, fIds);
        //receive features which shall be counted out of the feature base
        List<Feature> fValsCount = getFeatureValues(device, fIdsCount);

        //build the real set of featureExpressions which includes all instances
        //this is done by creating a set of feature expression which holds all features that were
        //received from the feature base, additionally count features are flagged in the second step
        logger.trace("preparing feature values");
        //first step with normal features
        for (Feature feature : fVals) {
            int step = 0;
            for (Pair<FeatureExpression, BooleanOperator> p : this.featureSet) {
                String targetId = p.getFirstElement().getFeatureId();
                if (targetId.equals(feature.getQualifiedIdWithoutInstance())) {
                    logger.trace("->feature assigned " + feature.getQualifiedId() + " with value " + feature.getValue());
                    if (p.getFirstElement().getFeatureValuePair().getSecondElement().getSecondElement().contains(Policy.GET_KEY)) {
                        ArrayList<String> rightFeatureVals = new ArrayList<String>();
                        rightFeatureVals.add(p.getFirstElement().getFeatureValuePair().getSecondElement().getSecondElement().substring(1));
                        List<Feature> getValues = getFeatureValues(device, rightFeatureVals);
                        for (Feature featureRight : getValues) {
                            FeatureExpression f = new FeatureExpression(feature, new Pair<String, Pair<ComparisonOperator,
                                    String>>(p.getFirstElement().getFeatureId(), new Pair<ComparisonOperator,
                                    String>(p.getFirstElement().getFeatureValuePair().getSecondElement().getFirstElement(),
                                    featureRight.getValue())), p.getFirstElement().getId(), p.getFirstElement().getScope());
                            f.setStep(step);
                            featureExpr.add(f);
                        }
                    } else {
                        FeatureExpression f = new FeatureExpression(feature, p.getFirstElement(), p.getFirstElement().getId());
                        f.setStep(step);
                        featureExpr.add(f);
                    }
                }
                step++;
            }
        }

        //add all feature id we need to look up to the blacklist tp prevent them from getting deleted later
        //fixes problems if evaluating signatures working on the same feature ids multiple times
        for (FeatureExpression e : featureExpr) {
            String id = e.getFeatureId();
            blacklisted.add(id);
        }

        //second step with features that should only be counted, this is necessary as count features cannot be
        //evaluated directly (evaluation loop shows how they are evaluated)
        logger.trace("preparing count-feature values");
        for (Feature feature : fValsCount) {
            for (Pair<FeatureExpression, BooleanOperator> p : this.featureSet) {
                if (p.getFirstElement().getFeatureId().contains(Policy.COUNT_KEY)) {
                    String targetId = p.getFirstElement().getFeatureId().substring(1);
                    if (targetId.equals(feature.getQualifiedIdWithoutInstance())) {
                        logger.trace("->count feature assigned " + feature.getQualifiedId());
                        FeatureExpression cF = new FeatureExpression(feature, p.getFirstElement(), p.getFirstElement().getId());
                        cF.setCounter();
                        featureExpr.add(cF);
                    }
                }
            }
        }

        //evaluate all feature expressions
        logger.debug("found " + featureExpr.size() + " features (including counters), starting evaluation...");

        //loop counter
        int k = 0;

        //check which kind of operator was used
        BooleanOperator op = BooleanOperator.AND;
        if (this.featureSet.size() > 1) {
            op = this.featureSet.get(1).getSecondElement();
        }

        //policy loop, i.e. this runs over each signature part parsed out of the policy
        for (int a = 0; a < this.featureSet.size(); a++) {
            Pair<FeatureExpression, BooleanOperator> p = this.featureSet.get(a);
            logger.trace("->stepping forward (" + k + "), evaluating against " + p.getFirstElement().getFeatureValuePair().getSecondElement().getSecondElement());

            k++;
            result = false;

            //shall we count the feature ids instead of evaluating them
            if (p.getFirstElement().getFeatureId().contains(Policy.COUNT_KEY)) {
                int counter = 0;
                logger.trace("found countkey- counting...");
                for (Feature feature : fValsCount) {
                    for (FeatureExpression fE : featureExpr) {
                        //check if the FE we are currently evaluating shall be evaluated by having a look onto
                        //the current signature part (outer loop)
                        if (feature.getQualifiedIdWithoutInstance().equals(p.getFirstElement().getFeatureId().substring(1))) {
                            //do the ids match, is it a valid FE and is it a countable expression
                            if (feature.getCategory().getId().equals(fE.getFeature().getCategory().getId()) && fE.isValid() && fE.isCounter()) {
                                counter++;
                                logger.trace(feature.getQualifiedId() + " ...(" + counter + ")");
                            }
                        }
                    }
                }
                //when counting is finished and something could be counted, create a new expression which represents the counting result
                Feature countFeature;
                if (counter > 0) {
                    countFeature = new Feature(fValsCount.get(0));
                } else {
                    countFeature = new Feature(p.getFirstElement().getFeatureId(), "0", new FeatureType(FeatureType.QUANTITIVE), new Category("irondetect"), null);
                }
                countFeature.setType(new FeatureType(FeatureType.QUANTITIVE));
                countFeature.setValue(Integer.toString(counter));
                //evaluate the expression, i.e. take the counted value and compare it against the desired (out of the policy) value
                result = (new FeatureExpression(countFeature, p.getFirstElement(), p.getFirstElement().getId())).evaluate(device);
            } else {

                //if we do not have to count, simply evaluate the appropriate parts of the expression set
                List<String> trueCat = new ArrayList<String>();
                for (int i = 0; i < featureExpr.size(); i++) {
                    FeatureExpression fE = featureExpr.get(i);
                    //check if we shall evaluate the current element
                    if (fE.getStep() == a) {

                        //evaluation returned true
                        if (fE.isValid() && !fE.isEvaluated() && !fE.isCounter() && fE.evaluate(device)) {
                            logger.trace("-->(" + i + ") returned true, scope is " + fE.getScope());

                            //apply scope filter
                            String root = this.applyScopeFilter(fE.getScope(), fE.getFeature().getCategory().getId());

                            trueCat.add(root);
                            //trueCat.add(fE.getFeature().getCategory().getId());


                            result = true;
                            //dont look at this FE again
                            fE.setEvaluated();
                            //still valid but eval was false
                        } else if (fE.isValid() && !fE.isCounter()) {
                            logger.trace("-->(" + i + ") returned false - trying to remove expressions");
                            logger.trace("-->root category is " + fE.getFeature().getCategory().getId());
                            for (int j = 0; j < featureExpr.size(); j++) {
                                String currId = featureExpr.get(j).getFeature().getCategory().getId();
                                String evalFalseId = fE.getFeature().getCategory().getId();
                                if (currId.contains(evalFalseId)) {
                                    //logger.trace("..." + featureExpr.get(j).getFeature().getQualifiedId() + " ("+ j + ") invalidated");
                                    if (!fE.isRevalidated()) {
                                        featureExpr.get(j).invalidate();
                                        //featureExpr.get(j).tagValidation();
                                    } else {
                                        featureExpr.get(j).tagValidation();
                                    }
                                }
                            }
                        } /*else {
                         logger.trace("--> FE not valid or counter: " + fE.getFeature().getQualifiedId() + ", value is " + fE.getFeature().getValue());
                         logger.trace("fEIsValid = " + fE.isValid() + ", fe.isCounter = " + fE.isCounter() + ",fe.isTagged = " + fE.isTagged() +
                         ", fe.isRevalidated = " + fE.isRevalidated());
                         }*/
                    }
                }

                for (FeatureExpression fE : featureExpr) {
                    if (fE.isTagged()) {
                        fE.invalidate();
                        fE.unTagValidation();
                    }
                }

                if (a < this.featureSet.size() - 1) {
                    logger.trace("revalidating expressions...");
                    String lookAheadId = this.featureSet.get(a + 1).getFirstElement().getFeatureId();
                    for (FeatureExpression fE : featureExpr) {
                        if (fE.isTagged()) {
                            fE.invalidate();
                        }
                        if (!fE.isValid()) {
                            for (String root : trueCat) {
                                //logger.trace("matching " + fE.getFeature().getCategory().getId() + " against " + root + ", look ahead id is " + lookAheadId);
                                if (fE.getFeature().getCategory().getId().contains(root)
                                        && fE.getFeature().getQualifiedIdWithoutInstance().equals(lookAheadId)) {
                                    fE.setRevalidated();
                                    fE.unTagValidation();
                                    //logger.trace("revalidated " + fE.getFeature().getQualifiedId()
                                    //        + " policy values: " + fE.getFeatureValuePair().getSecondElement().getSecondElement());
                                }
                            }
                        }
                    }
                }

                //debug
                //for(FeatureExpression fE : featureExpr) {
                //    logger.trace(fE.getFeature().getQualifiedId() + " value: " + fE.getFeature().getValue() + " VS " + fE.getFeatureValuePair().getSecondElement().getSecondElement() + " VRTE :" + fE.isValid() + fE.isRevalidated() + fE.isTagged() + fE.isEvaluated());
                //}

            }

            eTime = System.currentTimeMillis();

            //if we have and, return false if one step fails
            if (op == BooleanOperator.AND && !result) {
                logger.debug("step evaluation returned false... nothing more to do");
                logger.info("------------------------------Sig eval " + this.getId() + " finished with false----------------------");
				rlogger.reportResultsToLogger(device, this.id, SIGNATURE, false);
                super.printTimedResult(Signature.class, result, eTime - sTime);
                return false;
            }

            //one true is enough if we check it or style
            if (op == BooleanOperator.OR && result) {
                logger.debug("step evaluation returned true... nothing more to do");
                logger.info("------------------------------Sig eval " + this.getId() + " finished with true----------------------");
				rlogger.reportResultsToLogger(device, this.id, SIGNATURE, true);
                super.printTimedResult(Signature.class, result, eTime - sTime);
                return true;
            }

        }

        logger.info(
                "--------------------Sig eval " + this.getId() + " finished with " + result + "--------------------");
		rlogger.reportResultsToLogger(device, this.id, SIGNATURE, result);
        super.printTimedResult(Signature.class, result, eTime - sTime);
        return result;
    }


    private String applyScopeFilter(int scope, String root) {
        int idx;
        for (int s = 0; s < scope; s++) {
            idx = root.lastIndexOf(Policy.SUBCAT_KEY);
            if(idx > 0) {
                root = root.substring(0, idx);
            }
        }
        return root;
    }
}
