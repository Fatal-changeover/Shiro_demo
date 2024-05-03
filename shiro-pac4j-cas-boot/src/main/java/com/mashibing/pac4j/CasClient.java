package com.mashibing.pac4j;

import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.http.ajax.AjaxRequestResolver;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.core.redirect.RedirectActionBuilder;
import org.pac4j.core.util.CommonHelper;

/**
 * @author zjw
 * @description
 */
public class CasClient extends org.pac4j.cas.client.CasClient {

    public CasClient() {
        super();
    }

    public CasClient(CasConfiguration configuration) {
        super(configuration);
    }

    @Override
    public RedirectAction getRedirectAction(final WebContext context) {
        init();
        AjaxRequestResolver ajaxRequestResolver = getAjaxRequestResolver();
        RedirectActionBuilder redirectActionBuilder = getRedirectActionBuilder();
        // it's an AJAX request -> appropriate action
        if (ajaxRequestResolver.isAjax(context)) {
            logger.info("AJAX request detected -> returning the appropriate action");
            RedirectAction action = redirectActionBuilder.redirect(context);
            cleanRequestedUrl(context);
            return ajaxRequestResolver.buildAjaxResponse(action.getLocation(), context);
        }
        // authentication has already been tried -> unauthorized
        final String attemptedAuth = (String) context.getSessionStore().get(context, getName() + ATTEMPTED_AUTHENTICATION_SUFFIX);
        if (CommonHelper.isNotBlank(attemptedAuth)) {
            cleanAttemptedAuthentication(context);
            cleanRequestedUrl(context);
            // 跑抛出异常，页面401,只修改这个位置！！
            // throw HttpAction.unauthorized(context);
            return redirectActionBuilder.redirect(context);
        }

        return redirectActionBuilder.redirect(context);
    }

    private void cleanRequestedUrl(final WebContext context) {
        SessionStore<WebContext> sessionStore = context.getSessionStore();
        if (sessionStore.get(context, Pac4jConstants.REQUESTED_URL) != null) {
            sessionStore.set(context, Pac4jConstants.REQUESTED_URL, "");
        }
    }

    private void cleanAttemptedAuthentication(final WebContext context) {
        SessionStore<WebContext> sessionStore = context.getSessionStore();
        if (sessionStore.get(context, getName() + ATTEMPTED_AUTHENTICATION_SUFFIX) != null) {
            sessionStore.set(context, getName() + ATTEMPTED_AUTHENTICATION_SUFFIX, "");
        }
    }
}
