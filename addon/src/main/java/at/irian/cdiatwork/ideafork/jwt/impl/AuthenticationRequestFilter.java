/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package at.irian.cdiatwork.ideafork.jwt.impl;

import at.irian.cdiatwork.ideafork.jwt.api.AuthenticationRequired;
import at.irian.cdiatwork.ideafork.jwt.api.IdentityHolder;

import javax.annotation.Priority;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

import static javax.ws.rs.Priorities.AUTHENTICATION;

@RequestScoped

@AuthenticationRequired
@Provider

@Priority(AUTHENTICATION)
public class AuthenticationRequestFilter extends AuthenticationResponseFilter implements ContainerRequestFilter {
    @Inject
    private IdentityHolder identityHolder;

    @Inject
    private AuthenticationManager authenticationManager;

    @Inject
    private TokenExpirationManager expirationManager;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authorizationString = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        if (authorizationString == null) {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            return;
        }

        String token = authorizationString.substring("Bearer".length()).trim();

        try {
            authenticationManager.restoreIdentity(token);

            if (identityHolder.getAuthenticatedEMail() == null) {
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            } else {
                identityHolder.setCurrentToken(token);
            }
        } catch (Exception e) {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
}
