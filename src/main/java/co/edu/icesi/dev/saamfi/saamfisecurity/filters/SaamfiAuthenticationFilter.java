package co.edu.icesi.dev.saamfi.saamfisecurity.filters;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import co.edu.icesi.dev.saamfi.saamfisecurity.delegate.SaamfiDelegate;

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
		delegate = new SaamfiDelegate(saamfiUrl);
	}

	/**
	 * provider of JWT methods
	 */

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(HEADER_STRING);
		String username = null;
		String authToken = null;

		long sysid = 1;
		long instid = 1;

		boolean tokenValid = false;
		if (header != null && !header.equals("Bearer undefined") && header.startsWith(TOKEN_PREFIX)) {
			authToken = header.replace(TOKEN_PREFIX, "").trim();
			System.out.println("\n\ntoken: " + authToken + "\n\n");
			if (!authToken.trim().equals("null")) {
				if (delegate.validateToken(authToken)) {
					username = delegate.getUsernameFromJWT(authToken);
					sysid = delegate.getSysIdFromJWT(authToken);
					instid = delegate.getInstIdFromJWT(authToken);

					tokenValid = true;
				}
			}
		} else {
			logger.warn("couldn't find bearer string, will ignore the header");
		}
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (tokenValid && username != null && auth == null && sysid == systemId
				&& instid == institution) {
			Collection<SimpleGrantedAuthority> roles = delegate.getRolesFromJWT(authToken);
			if (roles == null) {
				roles = Collections.emptyList();
			}
			UserDetails userDetails = new org.springframework.security.core.userdetails.User(username, "", roles);

			UsernamePasswordAuthenticationToken authentication = delegate.getAuthentication(authToken, userDetails);
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			logger.info("usr:" + username + ", module auth, path:" + request.getServletPath());
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}

		filterChain.doFilter(request, response);

	}

}
