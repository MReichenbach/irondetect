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
package de.hshannover.f4.trust.irondetect.ifmap;



import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.ifmapj.messages.PollResult;
import de.hshannover.f4.trust.ifmapj.messages.ResultItem;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult.Type;
import de.hshannover.f4.trust.irondetect.model.Category;
import de.hshannover.f4.trust.irondetect.model.ContextParamType;
import de.hshannover.f4.trust.irondetect.model.ContextParameter;
import de.hshannover.f4.trust.irondetect.model.Feature;
import de.hshannover.f4.trust.irondetect.model.FeatureType;
import de.hshannover.f4.trust.irondetect.model.TrustLog;
import de.hshannover.f4.trust.irondetect.repository.FeatureBase;
import de.hshannover.f4.trust.irondetect.repository.FeatureBaseImpl;
import de.hshannover.f4.trust.irondetect.util.Pair;
import de.hshannover.f4.trust.irondetect.util.PollResultReceiver;

/**
 * @author bahellma
 *
 */
public class IfmapToFeatureMapper implements Runnable, PollResultReceiver {

    private static Logger logger = Logger.getLogger(IfmapToFeatureMapper.class);
    private FeatureBase featureBase;
    private LinkedBlockingQueue<PollResult> incomingResults = new LinkedBlockingQueue<PollResult>();

    public IfmapToFeatureMapper() {
        this.featureBase = FeatureBaseImpl.getInstance();
    }

    /**
     * Run the handler loop. The following steps are performed: <p> 1. Wait for new SearchResults in the queue.<br> 2. If new SearchResults arrive:<br> 2.1 ...
     * 3. Start at 1. again.
     */
    @Override
    public void run() {
        logger.info(IfmapToFeatureMapper.class.getSimpleName()
                + " has started.");

        try {
            while (!Thread.currentThread().isInterrupted()) {
                PollResult lastPollResult = incomingResults.take();
                onNewPollResult(lastPollResult);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.info("Got interrupt signal while waiting for new work, exiting ...");
        } finally {
            logger.info("Shutdown complete.");
        }
    }

    /**
     * Map a new {@link SearchResult} to a new {@link Feature} instance and put it into the {@link FeatureBase}.
     *
     * @param lastPollResult the last {@link SearchResult} inside the incoming queue
     */
    private void onNewPollResult(PollResult lastPollResult) {

        logger.info("PollResult received...");

        //CoreComponent and deleteFlag - true if CC was deleted
        ArrayList<Pair<String, Pair<Feature, Boolean>>> coreComps = new ArrayList<Pair<String, Pair<Feature, Boolean>>>();

        //
        for (SearchResult searchResult : lastPollResult.getResults()) {

            logger.debug("Parsing searchResult " + searchResult.getName());

            String device = null;
            for (ResultItem resultItem : searchResult.getResultItems()) {

                logger.trace("Parsing resultItem " + resultItem.toString());

                //searchResult ? device identifier : only categories
                if (searchResult.getType() == Type.searchResult) {
                    if (resultItem.getIdentifier1() != null) {
                        if (resultItem.getIdentifier1() instanceof Device) {
                            device = ((Device) resultItem.getIdentifier1()).getName();
                            logger.trace("Found device=" + device);
                        } else if (resultItem.getIdentifier2() != null && resultItem.getIdentifier2() instanceof Device) {
                            device = ((Device) resultItem.getIdentifier2()).getName();
                            logger.trace("Found device=" + device);
                        }
                    }
                }//device

                Category c1 = null;
                if ((resultItem.getIdentifier1() != null) && (resultItem.getIdentifier1() instanceof Identity)) {
                    Identity i = (Identity) resultItem.getIdentifier1();
                    c1 = new Category(i.getName());
                    logger.trace("Found category=" + i.getName());
                    if (device == null) {
                        device = i.getAdministrativeDomain();
                    }
                }

                Category c2 = null;
                if ((resultItem.getIdentifier2() != null) && (resultItem.getIdentifier2() instanceof Identity)) {
                    Identity i = (Identity) resultItem.getIdentifier2();
                    c2 = new Category(i.getName());
                    logger.trace("Found category=" + i.getName());
                    if (device == null) {
                        device = i.getAdministrativeDomain();
                    }
                }

                Category top = null;
                if (c2 != null && c1 != null) {
                    if (c1.getId().length() <= c2.getId().length()) {
                        top = c1;
                        top.addSubCategory(c2);
                    } else {
                        top = c2;
                        c2.addSubCategory(c1);
                    }
                } else if (c2 != null) {
                    top = c2;
                } else {
                    top = c1;
                }

                if (top != null) {
                    logger.trace("resultItem root category=" + top.getId());
                }

                HashMap<Integer, TrustLog> trustTokenMap = new HashMap<Integer, TrustLog>();

                for (Document meta : resultItem.getMetadata()) {

                    logger.trace("Parsing metadata...");

                    String id = "undefined";
                    FeatureType type = new FeatureType(FeatureType.ARBITRARY);
                    String value = "";
                    Set<ContextParameter> ctx = new HashSet<ContextParameter>();
                    int trustTokenId = 0;
                    logger.trace("NodeName=" + meta.getDocumentElement().getLocalName());
                    //feature
                    if (meta.getDocumentElement().getLocalName().equals("feature")) {
                        NamedNodeMap map = meta.getDocumentElement().getAttributes();
                        boolean hasTrustLog = false;
                        for (int i = 0; i < map.getLength(); i++) {
                            String tmp = map.item(i).getNodeName();
                            if (tmp.equalsIgnoreCase("trust-token-id")) {
                                trustTokenId = Integer.parseInt(map.item(i).getNodeValue());
                                hasTrustLog = true;
                            } else if (tmp.equalsIgnoreCase("ctxp-timestamp")) {
                                ctx.add(new ContextParameter(new ContextParamType(ContextParamType.DATETIME), map.item(i).getNodeValue()));
                            } else if (tmp.equalsIgnoreCase("ctxp-position")) {
                                ctx.add(new ContextParameter(new ContextParamType(ContextParamType.LOCATION), map.item(i).getNodeValue()));
                            } else {
                                ctx.add(new ContextParameter(new ContextParamType(ContextParamType.OTHERDEVICES), map.item(i).getNodeValue()));
                            }
                        }
                        NodeList elems = meta.getDocumentElement().getChildNodes();
                        for (int i = 0; i < elems.getLength(); i++) {
                            String nodeName = elems.item(i).getNodeName();
                            logger.trace("ChildNodeName=" + nodeName);
                            if (nodeName.equalsIgnoreCase("id")) {
                                id = elems.item(i).getTextContent();
                            } else if (nodeName.equalsIgnoreCase("type")) {
                                if (elems.item(i).getTextContent().equalsIgnoreCase("quantitive")) {
                                    type = new FeatureType(FeatureType.QUANTITIVE);
                                } else if (elems.item(i).getTextContent().equalsIgnoreCase("qualified")) {
                                    type = new FeatureType(FeatureType.QUALIFIED);
                                } else {
                                    type = new FeatureType(FeatureType.ARBITRARY);
                                }
                            } else if (nodeName.equalsIgnoreCase("value")) {
                                value = elems.item(i).getTextContent();
                            }
                        }
                        logger.trace("Adding feature: dev=" + device + ",id=" + id + ",value=" + value + ", type=" + type + ",cat=" + top + ",ctx=" + ctx);
                        Feature found = new Feature(id, value, type, top, ctx);
                        if (hasTrustLog) {
                            TrustLog tl = null;
                            if (trustTokenMap.containsKey(new Integer(trustTokenId))) {
                                tl = trustTokenMap.get(new Integer(trustTokenId));
                                ctx.add(new ContextParameter(new ContextParamType(ContextParamType.TRUSTLEVEL), Integer.toString(tl.getTrustLevel())));
                            } else {
                                tl = new TrustLog(trustTokenId);
                                trustTokenMap.put(new Integer(trustTokenId), tl);
                            }
                            found.setTrustLog(tl);
                            logger.trace("Found trust-token-id " + trustTokenId + "... creating TrustLog");
                        }
                        if (searchResult.getType() == Type.deleteResult) {
                            coreComps.add(new Pair<String, Pair<Feature, Boolean>>(device, new Pair<Feature, Boolean>(found, true)));
                        } else {
                            coreComps.add(new Pair<String, Pair<Feature, Boolean>>(device, new Pair<Feature, Boolean>(found, false)));
                        }
                        //feature

                        //trust
                    } else if (meta.getDocumentElement().getLocalName().equals("trust-token-metadata")) {
                        logger.trace("found trust-token-metadata...");
                        NamedNodeMap map = meta.getDocumentElement().getAttributes();
                        for (int i = 0; i < map.getLength(); i++) {
                            String tmp = map.item(i).getNodeName();
                            if (tmp.equalsIgnoreCase("trust-token-id")) {
                                trustTokenId = Integer.parseInt(map.item(i).getNodeValue());
                            }
                        }
                        NodeList elems = meta.getDocumentElement().getChildNodes();
                        TrustLog tl = null;
                        if (trustTokenMap.containsKey(new Integer(trustTokenId))) {
                            tl = trustTokenMap.get(new Integer(trustTokenId));
                        } else {
                            tl = new TrustLog(trustTokenId);
                            trustTokenMap.put(new Integer(trustTokenId), tl);
                        }
                        for (int i = 0; i < elems.getLength(); i++) {
                            String nodeName = elems.item(i).getNodeName();
                            logger.trace("ChildNodeName=" + nodeName);
                            //trust level
                            if (nodeName.equalsIgnoreCase("trust-level")) {
                                tl.setTrustLevel(Integer.parseInt(elems.item(i).getTextContent()));
                            } else if (nodeName.equalsIgnoreCase("spr-process-sender")) {
                                tl.setProcessSenderSecurityPropertyRatings(this.parseRating(elems.item(i).getTextContent()));
                            } else if (nodeName.equalsIgnoreCase("spr-transmit-sender-receiver")) {
                                tl.setTransmitSenderSecurityPropertyRatings(this.parseRating(elems.item(i).getTextContent()));
                            } else if (nodeName.equalsIgnoreCase("spr-process-provider")) {
                                tl.setProcessProviderSecurityPropertyRatings(this.parseRating(elems.item(i).getTextContent()));
                            } else if (nodeName.equalsIgnoreCase("spr-transmit-provider-receiver")) {
                                tl.setTransmitProviderSecurityPropertyRatings(this.parseRating(elems.item(i).getTextContent()));
                            }
                        }
                    }
                }
            }
        }

        logger.debug("-----------------------Features found:----------------------");
        if (coreComps.size() > 0) {
            for (Pair<String, Pair<Feature, Boolean>> pair : coreComps) {
                Feature curr = pair.getSecondElement().getFirstElement();
                if (curr.getTrustLog() != null) {
                    curr.getContextParameters().add(new ContextParameter(new ContextParamType(ContextParamType.TRUSTLEVEL), Integer.toString(curr.getTrustLog().getTrustLevel())));
                }
                logger.debug("device=" + pair.getFirstElement() + ", " + pair.getSecondElement().getFirstElement());
            }
            logger.debug("Sending " + coreComps.size() + " features to FeatureBase");
            logger.debug("------------------------------------------------------------");
            this.featureBase.addNewFeatures(coreComps, false);
        } else {
            logger.debug("No features were sent to FeatureBase.");
            logger.debug("------------------------------------------------------------");
        }
    }

    /**
     * Submit a new {@link PollResult} to this {@link IfmapToFeatureMapper}.
     *
     * @param pollResult the new {@link PollResult} to submit
     */
	@Override
	public void submitNewPollResult(PollResult pollResult) {
        try {
            incomingResults.put(pollResult);
            logger.trace("PollhResult was inserted");
        } catch (InterruptedException e) {
            logger.error("Could not add PollResult to IF-MAP to Feature-Mapper:"
                    + e.getMessage());
        }
    }
    
    
    private ArrayList<Integer> parseRating(String textContent) {
        ArrayList<Integer> result = new ArrayList<Integer>();
        String[] sps = textContent.split(";");
        for (int i = 1; i <sps.length; i++) {
            String[] reA = sps[i].split(":");
            result.add(Integer.parseInt(reA[1]));
        }
        
        return result;
    }
}
