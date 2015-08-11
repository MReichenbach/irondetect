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
package de.hshannover.f4.trust.irondetect.engine;



import java.io.FileNotFoundException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.model.Policy;
import de.hshannover.f4.trust.irondetect.policy.parser.ParseException;
import de.hshannover.f4.trust.irondetect.policy.parser.PolicyFactory;
import de.hshannover.f4.trust.irondetect.policy.parser.TokenMgrError;
import de.hshannover.f4.trust.irondetect.util.Configuration;
import de.hshannover.f4.trust.irondetect.util.Constants;
import de.hshannover.f4.trust.irondetect.util.event.Event;
import de.hshannover.f4.trust.irondetect.util.event.EventReceiver;
import de.hshannover.f4.trust.irondetect.util.event.EventType;
import de.hshannover.f4.trust.irondetect.util.event.FeatureBaseUpdateEvent;
import de.hshannover.f4.trust.irondetect.util.event.TrainingData;
import de.hshannover.f4.trust.irondetect.util.event.TrainingDataLoadedEvent;
import de.hshannover.f4.trust.irondetect.util.event.TriggerUpdateEvent;
import java.util.HashMap;

/**
 *
 * Implements the state machine of the detection engine. Holds the policy.
 * Generates profiles from policy. Testing / Training dispatching
 *
 * @author ibente
 *
 */
public class Processor implements EventReceiver, Runnable {

    private Logger logger = Logger.getLogger(Processor.class);
    private LinkedBlockingQueue<Event> incomingEvents;
    private Policy policy;
//	private HashMap<String, Policy> profiles; // FIXME is this needed?
    private boolean isTraining; // TODO state machine
    private Map<String, TrainingData> trainingDataMap;

	public Policy getPolicy() {
		return policy;
	}
            
    /**
     * Thread-safe and performant Singleton
     */
    private static Processor instance = new Processor();

    private Processor() {
        try {
            this.incomingEvents = new LinkedBlockingQueue<Event>();
            this.trainingDataMap = null;
//			this.profiles = new HashMap<String, Policy>();
            // default state is testing
//			setToTesting();
            setTotraining();
            // Parse policy
            this.policy = PolicyFactory.readPolicy(Configuration.policyFile());
        } catch (FileNotFoundException e) {
            logger.error("Policy file could not be loaded: " + e.getMessage() + ", " + e.getCause());
            System.exit(Constants.RETURN_CODE_ERROR_POLICY_NOT_FOUND);
        } catch (ParseException e) {
            logger.error("Policy could not be parsed: " + e.getMessage() + ", " + e.getCause());
            System.exit(Constants.RETURN_CODE_ERROR_POLICY_PARSER_FAILED);
        } catch (TokenMgrError e) {
            logger.error("Policy could not be parsed: " + e.getMessage() + ", " + e.getCause());
            System.exit(Constants.RETURN_CODE_ERROR_POLICY_PARSER_FAILED);
        }
    }
    
    public Map<String, TrainingData> getTrainingDataMap(){
        return this.trainingDataMap;
    }

    /**
     * Singleton
     *
     * @return
     */
    public static Processor getInstance() {
        return Processor.instance;
    }

    /**
     * @return true if irondetect is training
     */
    public boolean isTraining() {
        return this.isTraining;
    }

    /**
     * @return true if irondetect is testing
     */
    public boolean isTesting() {
        return !this.isTraining;
    }

    /**
     * set to training mode
     */
    public synchronized void setTotraining() {
        logger.info("Set to training mode.");
        this.isTraining = true;
    }

    /**
     * set to testing mode
     */
    public synchronized void setToTesting() {
        logger.info("Set to testing mode.");
        this.isTraining = false;
    }

    @Override
    public void run() {
        logger.info(Processor.class.getSimpleName() + " has started.");

        try {
            while (!Thread.currentThread().isInterrupted()) {
                Event e = incomingEvents.take();
                onNewPollResult(e);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.info("Got interrupt signal while waiting for new work, exiting ...");
        } finally {
            logger.info("Shutdown complete.");
        }
    }

    private void onNewPollResult(Event e) {
        logger.info("Got new event: " + e.toString());

        if (isTraining) {
            logger.info("training triggered by new event: " + e);
            if (e.getType() == EventType.TRAINING_DATA_LOADED) {
                TrainingDataLoadedEvent event = (TrainingDataLoadedEvent) e;
                Map<String, TrainingData> payload = event.getPayload();
                logger.info("Features have changed on " + payload.size()
                        + " devices.");
                this.trainingDataMap = payload; // FIXME ugly

                for (String singleDevice : this.trainingDataMap.keySet()) {
                    logger.trace("Payload size for device '" + singleDevice + "' is: " + trainingDataMap.get(singleDevice).getFeatureIDs().size());
                    policy.train(singleDevice);
                }
            } // trigger updates are ignored

            // all training data was loaded and "trained", so set to testing mode
            this.setToTesting();
            logger.info("Training finished -> switching to testing phase.");
        } else {
            logger.info("policy check triggered by new event: " + e);
            if (e.getType() == EventType.FEATURE_BASE_UPDATE) {
                // a Map containing Lists of FeatureIds that changed (new,
                // updated, deleted) during the FeatureBaseUpdate for each
                // device.
                Map<String, Set<String>> payload = ((FeatureBaseUpdateEvent) e)
                        .getPayload();
                logger.info("Features have changed on " + payload.size()
                        + " devices.");

                for (String s : payload.keySet()) {
                    logger.trace("Payload size for device '" + s + "' is: " + payload.get(s).size());
                    policy.check(s, payload.get(s));
                }

            } else if (e.getType() == EventType.TRIGGER) {
                TriggerUpdateEvent triggerEvent = (TriggerUpdateEvent) e;
                Trigger t = triggerEvent.getTrigger();
                logger.info("Trigger update was received: " + t);
                logger.trace("Evaluating rule " + t.getRootRule() + "'");
                t.getRootRule().evaluate(t.getDevice());
            }
            logger.info("Finished testing of incoming poll result.");
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * de.hshannover.f4.trust.irondetect.util.EventReceiver#submitNewEvent
     * (de.hshannover.f4.trust.irondetect.util.EventType)
     */
    @Override
    public synchronized void submitNewEvent(Event e) {
        try {
            this.incomingEvents.put(e);
            logger.trace("Event was inserted");
        } catch (InterruptedException e1) {
            logger.error("Could not add Event to Processor:" + e1.getMessage());
        }
    }
}
