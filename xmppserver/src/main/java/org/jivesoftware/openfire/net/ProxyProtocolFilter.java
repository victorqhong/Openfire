/*
 * Copyright (C) 2020 Victor Hong. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.net;

import java.lang.StringBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MINA filter that will process proxy protocol data if present
 *
 * @author Victor Hong
 */
public class ProxyProtocolFilter extends IoFilterAdapter {
    
    private final static Logger Log = LoggerFactory.getLogger(ProxyProtocolFilter.class);

    public  final static String PROXY_ADDRESS = "PROXY_ADDRESS";

    private final int PROXY_PROTOCOL_V1_MAX_SIZE = 107;

    @Override
    public void messageReceived(NextFilter nextFilter, IoSession session, Object message)
            throws Exception {

        String proxyAddress = (String)session.getAttribute(PROXY_ADDRESS);
        if (proxyAddress != null) {
            super.messageReceived(nextFilter, session, message);
            return;
        }

        IoBuffer buf = (IoBuffer)message;
        if (buf == null || buf.remaining() < 5) {
            super.messageReceived(nextFilter, session, message);
            return;
        }

        char p = (char)buf.get();
        char r = (char)buf.get();
        char o = (char)buf.get();
        char x = (char)buf.get();
        char y = (char)buf.get();

        if (p != 'P' || r != 'R' || o != 'O' || x != 'X' || y != 'Y') {
            super.messageReceived(nextFilter, session, buf.position(0));
            return;
        }

        StringBuffer buffer = new StringBuffer(PROXY_PROTOCOL_V1_MAX_SIZE);
        buffer.append("PROXY");

        char lastValue = (char)0;
        boolean success = false;

        while (buf.hasRemaining() && buffer.length() <= PROXY_PROTOCOL_V1_MAX_SIZE) {
            char value = (char)buf.get();
            buffer.append(value);
            if (lastValue == '\r' && value == '\n') {
                success = true;
                break;
            }

            lastValue = value;
        }

        if (!success) {
            Log.error("Could not parse proxy protocol data");
            session.closeNow();
            return;
        }

        String proxyData = buffer.toString();
        String[] elements = proxyData.split(" ");
        if (elements.length != 6) {
            Log.error("Error parsing proxy protocol data");
            session.closeNow();
            return;
        }

        session.setAttribute(PROXY_ADDRESS, elements[2]);
        super.messageReceived(nextFilter, session, buf);
    }
}
