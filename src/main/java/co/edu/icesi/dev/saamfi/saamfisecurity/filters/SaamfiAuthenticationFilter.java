package co.edu.icesi.dev.saamfi.saamfisecurity.filters;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import co.edu.icesi.dev.saamfi.saamfisecurity.delegate.SaamfiDelegate;
import co.edu.icesi.dev.saamfi.saamfisecurity.entities.UserDetailToken;

public class SaamfiAuthenticationFilter extends OncePerRequestFilter {

	/**
	 * String to retrieve authentication in header
	 */
	public static final String HEADER_STRING = "Authorization";

	/**
	 * String to remove the token prefix
	 */
	public static final String TOKEN_PREFIX = "Bearer";

	private SaamfiDelegate delegate;

	private long systemId;

	private long institution;

	public SaamfiAuthenticationFilter(String saamfiUrl, long systemId, long institution) {
		this.systemId = systemId;
		this.institution = institution;
		delegate = new SaamfiDelegate(saamfiUrl, systemId, institution);
	}

	public SaamfiDelegate getDelegate() {
		return delegate;
	}

	/**
	 * provider of JWT methods
	 */

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(HEADER_STRING);
		String authToken = null;

		UserDetailToken userDetailToken = null;
		if (header != null && !header.equals("Bearer undefined") && header.startsWith(TOKEN_PREFIX)) {
			authToken = header.replace(TOKEN_PREFIX, "").trim();
			if (!authToken.trim().equals("null")) {
				try {
					userDetailToken = delegate.validateToken(authToken);
				} catch (Exception e) {
					manageTokenInvalid(e, response);
					return;
				}

			}
		} else {
			logger.warn("couldn't find bearer string, will ignore the header");
		}
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (userDetailToken != null && auth == null && userDetailToken.getSystem() == systemId && userDetailToken.getInstitution() == institution) {
			UsernamePasswordAuthenticationToken authentication = delegate.getAuthentication(authToken, userDetailToken);
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			logger.info("usr:" + userDetailToken + ", module auth, path:" + request.getServletPath());
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}

		filterChain.doFilter(request, response);

	}

	private void manageTokenInvalid(Exception exception, HttpServletResponse response) {
		response.setContentType("application/json;charset=UTF-8");
		HashMap<String, String> responseBo = new HashMap<String, String>();
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		responseBo.put("message", exception.fillInStackTrace().toString());
		exception.printStackTrace();
		JSONObject responseJson = new JSONObject(responseBo);
		try {
			response.getWriter().write(responseJson.toJSONString());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
