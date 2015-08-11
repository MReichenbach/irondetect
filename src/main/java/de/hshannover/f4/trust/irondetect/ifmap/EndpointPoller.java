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
import java.util.List;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.ifmapj.channel.ARC;
import de.hshannover.f4.trust.ifmapj.exception.EndSessionException;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.messages.PollResult;
import de.hshannover.f4.trust.irondetect.util.Constants;
import de.hshannover.f4.trust.irondetect.util.PollResultReceiver;
import de.hshannover.f4.trust.irondetect.util.PollResultSender;

public class EndpointPoller implements Runnable, PollResultSender {

	private Logger logger = Logger.getLogger(EndpointPoller.class);

	private static EndpointPoller instance;

	private ARC mArc;

	private List<PollResultReceiver> mPollResultReceiver;

	private EndpointPoller() {
		mPollResultReceiver = new ArrayList<PollResultReceiver>();
	}

	public synchronized static EndpointPoller getInstance() {
		if (instance == null) {
			instance = new EndpointPoller();
		}
		return instance;
	}

	@Override
	public void run() {
		if (mArc == null) {
			throw new RuntimeException("The ARC is null. Befor start this thread set the ARC.");
		}

		while (!Thread.currentThread().isInterrupted()) {
			try {
				PollResult pollResult = mArc.poll();
				onNewPollResult(pollResult);
			} catch (IfmapErrorResult e) {
				logger.error("Got IfmapError: " + e.getMessage() + ", " + e.getCause());
			} catch (EndSessionException e) {
				logger.error("The session with the MAP server was closed: " + e.getMessage() + ", " + e.getCause());
				System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_EXCEPTION);
			} catch (IfmapException e) {
				logger.error("Error at polling the MAP server: " + e.getMessage() + ", " + e.getCause());
				System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_EXCEPTION);
			}
		}
	}

	public void setArc(ARC arc) {
		mArc = arc;
	}

	@Override
	public void addPollResultReceiver(PollResultReceiver prReceiver) {
		if (!this.mPollResultReceiver.contains(prReceiver)) {
			this.mPollResultReceiver.add(prReceiver);
		}
	}

	private void onNewPollResult(PollResult pollResult) {
		for (PollResultReceiver prReceiver : mPollResultReceiver) {
			prReceiver.submitNewPollResult(pollResult);
		}
		logger.trace("PollResult were send to registered receivers.");
	}
}
