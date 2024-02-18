package com.aws.authorizer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.aws.exception.JwtTokenMalformedException;
import com.aws.exception.JwtTokenMissingException;
import com.aws.model.AuthorizerResponse;
import com.aws.model.PolicyDocument;
import com.aws.model.Statement;
import com.aws.utils.JwtUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class LambdaJwtAuthorizer implements RequestHandler<APIGatewayProxyRequestEvent, AuthorizerResponse> {
    @Override
    public AuthorizerResponse handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> headers = event.getHeaders();
        String token = headers.get("authorization");
        Map<String, String> ctx = new HashMap<>();

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = event.getRequestContext();
        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                System.getenv("AWS_REGION"),
                proxyContext.getAccountId(),
                proxyContext.getApiId(),
                proxyContext.getStage(),
                proxyContext.getHttpMethod(),
                "*");

        String effect = "Allow";
        try {
            JwtUtil.validateToken(token);
            ctx.put("message", "Success");
        } catch (JwtTokenMalformedException |
                 JwtTokenMissingException e) {
            effect = "Deny";
            ctx.put("message", e.getMessage());
        }

        Statement statement = Statement.builder().resource(arn).effect(effect).build();

        PolicyDocument policyDocument = PolicyDocument.builder().statements(Collections.singletonList(statement))
                .build();
        return AuthorizerResponse.builder().principalId(proxyContext.getAccountId()).policyDocument(policyDocument)
                .context(ctx).build();
    }
}
