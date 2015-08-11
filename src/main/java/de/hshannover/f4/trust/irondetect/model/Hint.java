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



import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.engine.Processor;
import de.hshannover.f4.trust.irondetect.procedure.ProcedureRepository;
import de.hshannover.f4.trust.irondetect.procedure.Procedureable;
import de.hshannover.f4.trust.irondetect.repository.FeatureBase;
import de.hshannover.f4.trust.irondetect.util.event.TrainingData;

/**
 *
 * Hint that can be evaluated. Ties definitions from policy together with
 * concrete instances from the {@link FeatureBase}.
 *
 * @author jvieweg
 * @author ib
 *
 */
public class Hint implements PolicyData {

    private Logger logger = Logger.getLogger(this.getClass());
    private String id;
    private List<Feature> featureSet;
    private List<String> featureIds;
    private Procedure procedureFromPolicy;
    private Procedureable procedureFromRepository;
    private boolean initialized;

    public Hint() {
        this.featureIds = new ArrayList<String>();
        this.featureSet = new ArrayList<Feature>();
    }

    /**
     * @return the featureSet
     */
    public List<Feature> getFeatureSet() {
        return featureSet;
    }

    /**
     * @param featureSet the featureSet to set, ignores null
     */
    public void setFeatureSet(List<Feature> featureSet) {
        if (featureSet != null) {
            this.featureSet = featureSet;
        }
    }

    /**
     * @return the procedure
     */
    public Procedure getProcedure() {
        return procedureFromPolicy;
    }

    /**
     * @param procedure the procedure to set
     */
    public void setProcedure(Procedure procedure) {
        this.procedureFromPolicy = procedure;
    }

    /**
     *
     * @param fIds null is ignored
     */
    public void setFeatureIds(List<String> fIds) {
        if (fIds != null) {
            this.featureIds = fIds;
        }
    }

    public List<String> getFeatureIds() {
        return this.featureIds;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder fSetStr = new StringBuilder("featureSet=");

        for (Feature f : featureSet) {
            fSetStr.append(f.toString());
        }
        return "Hint [" + fSetStr.toString() + ", procedure="
                + procedureFromPolicy + ", " + super.toString() + "]";
    }

    public double evaluate(String device, Anomaly anomaly) {

        logger.debug("evaluating hint <" + getId() + "> as part of anomaly <" + anomaly.getId() + "> with procedure <"
                + getProcedure().getId() + ">" + " for device <" + device + ">");
  

        if (this.featureSet == null) {
            logger.trace("featureSet is null. returning ...");
            return 0;
        }
        
        logger.debug("size of featureSet in hint = " + featureSet.size());

        if (!initialized) {
            // load correct Procedure from ProcedureRepository
            this.procedureFromRepository = ProcedureRepository.getInstance()
                    .getProcedureById(device, anomaly.getId(), getId(), getProcedure().getId());
            this.procedureFromRepository.setUp(this.procedureFromPolicy.getConfig());
            initialized = true;
        }

        // training or testing?
        if (Processor.getInstance().isTraining()) {
            logger.trace("training for hint " + this.toString());
            // get training data from processor
            TrainingData trainingData = Processor.getInstance().getTrainingDataMap().get(device);
            this.procedureFromRepository.train(featureSet, anomaly.getContextSet(), trainingData.getStartTime(), trainingData.getEndTime());
            return 0; // FIXME we simply do return 0. Should be ignored during training anyway.
        } else {
            logger.trace("testing for hint " + this.toString());
            return this.procedureFromRepository.calculate(featureSet, anomaly.getContextSet()).value;
        }

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
}
