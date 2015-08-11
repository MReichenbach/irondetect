package de.hshannover.f4.trust.irondetect.util;

import de.hshannover.f4.trust.ifmapj.messages.PollResult;

/**
 * 
 * @author Marcel Reichenbach
 *
 */
public interface PollResultReceiver {

	/**
	 * @param e
	 */
	public void submitNewPollResult(PollResult pr);
}
