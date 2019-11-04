/*
 *  Copyright (C) 2019 GeoSolutions S.A.S.
 *  http://www.geo-solutions.it
 *
 *  GPLv3 + Classpath exception
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package it.geosolutions.geostore.core.dao.ldap.impl;

import java.util.List;
import javax.naming.directory.DirContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.ldap.control.SortControlDirContextProcessor;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextProcessor;
import org.springframework.ldap.core.LdapTemplate;
import com.googlecode.genericdao.search.Filter;
import com.googlecode.genericdao.search.ISearch;
import it.geosolutions.geostore.core.dao.ldap.impl.LdapBaseDAOImpl.NullDirContextProcessor;

public abstract class LdapBaseDAOImpl {
    
    public static final class NullDirContextProcessor implements DirContextProcessor {
        public void postProcess(DirContext ctx) {
            // Do nothing
        }

        public void preProcess(DirContext ctx) {
            // Do nothing
        }
    }
    
    protected String searchBase = "";
    protected String baseFilter = "cn=*";
    protected  String nameAttribute = "cn";
    protected  String descriptionAttribute = "description";
    protected boolean sortEnabled = false;
    
    protected ContextSource contextSource;
    protected LdapTemplate template;
    
    public LdapBaseDAOImpl(ContextSource contextSource) {
        this.contextSource = contextSource;
        template = new LdapTemplate(contextSource);
    }
    
    public String getSearchBase() {
        return searchBase;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    public String getFilter() {
        return baseFilter;
    }

    public void setFilter(String filter) {
        this.baseFilter = filter;
    }

    public String getNameAttribute() {
        return nameAttribute;
    }

    public void setNameAttribute(String nameAttribute) {
        this.nameAttribute = nameAttribute;
    }

    public String getDescriptionAttribute() {
        return descriptionAttribute;
    }

    public void setDescriptionAttribute(String descriptionAttribute) {
        this.descriptionAttribute = descriptionAttribute;
    }
    
    
    protected DirContextProcessor getProcessorForSearch(ISearch search) {
        if (sortEnabled && search.getSorts() != null && search.getSorts().size() == 1) {
            return new SortControlDirContextProcessor(nameAttribute);
        }
        return new NullDirContextProcessor();
    }
    
    public boolean isSortEnabled() {
        return sortEnabled;
    }

    public void setSortEnabled(boolean sortEnabled) {
        this.sortEnabled = sortEnabled;
    }

    protected String combineFilters(String baseFilter, String ldapFilter) {
        if ("".equals(baseFilter)) {
            return ldapFilter;
        }
        if ("".equals(ldapFilter)) {
            return baseFilter;
        }
        return "(& ("+baseFilter+") ("+ldapFilter+"))";
    }

    protected String getLdapFilter(ISearch search) {
        String currentFilter = "";
        for (Filter filter : search.getFilters()) {
            currentFilter = combineFilters(currentFilter, getLdapFilter(filter));
        }
        return currentFilter;
    }

    private String getLdapFilter(Filter filter) {
        switch(filter.getOperator()) {
            case Filter.OP_EQUAL:
                return filter.getProperty() + "=" + filter.getValue().toString();
            //TODO: implement all operators
        }
        return "";
    }
    
    protected Expression getSearchExpression(List<Filter> filters) {
        String expression = "";
        for (Filter filter: filters) {
            expression = combineExpressions(expression, getSearchExpression(filter));
        }
        if ("".equals(expression)) {
            expression = "true";
        }
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expression);
    }

    protected String combineExpressions(String expression, String searchExpression) {
        if ("".equals(expression)) {
            return searchExpression;
        }
        if ("".equals(searchExpression)) {
            return expression;
        }
        return "("+expression+") && ("+searchExpression+")";
    }

    private String getSearchExpression(Filter filter) {
        switch(filter.getOperator()) {
            case Filter.OP_EQUAL:
                return filter.getProperty() + "==" + filter.getValue().toString();
            //TODO: implement all operators
        }
        return "";
    }

}
