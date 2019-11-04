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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.directory.SearchControls;
import org.apache.log4j.Logger;
import org.springframework.ldap.control.SortControlDirContextProcessor;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DirContextProcessor;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.transaction.annotation.Transactional;
import com.googlecode.genericdao.search.ISearch;
import it.geosolutions.geostore.core.dao.UserDAO;
import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.UserAttribute;

/**
 * Class UserDAOImpl.
 * 
 * @author Tobia di Pisa (tobia.dipisa at geo-solutions.it)
 * @author ETj (etj at geo-solutions.it)
 */
@Transactional(value = "geostoreTransactionManager")
public class UserDAOImpl extends LdapBaseDAOImpl implements UserDAO {

    private static final Logger LOGGER = Logger.getLogger(UserDAOImpl.class);

    protected Map<String, String> attributesMapper = new HashMap<String, String>();
    
    public UserDAOImpl(ContextSource contextSource) {
        super(contextSource);
    }
    
    public Map<String, String> getAttributesMapper() {
        return attributesMapper;
    }

    public void setAttributesMapper(Map<String, String> attributesMapper) {
        this.attributesMapper = attributesMapper;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#persist(T[])
     */
    @Override
    public void persist(User... entities) {
        
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#findAll()
     */
    @Override
    public List<User> findAll() {
        return ldapSearch(baseFilter, new NullDirContextProcessor());
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#search(com.trg.search.ISearch)
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<User> search(ISearch search) {
        return ldapSearch(combineFilters(baseFilter, getLdapFilter(search)), getProcessorForSearch(search));
    }

    protected List<User> ldapSearch(String filter, DirContextProcessor processor) {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return template.search(searchBase, filter, controls, new AbstractContextMapper() {
            int counter = 1;
            @Override
            protected User doMapFromContext(DirContextOperations ctx) {
                User user = new User();
                user.setId((long)counter++);
                user.setEnabled(true);
                user.setName(ctx.getStringAttribute(nameAttribute));
                List<UserAttribute> attributes = new ArrayList<UserAttribute>();
                for (String ldapAttr : attributesMapper.keySet()) {
                    String value = ctx.getStringAttribute(ldapAttr);
                    String userAttr = attributesMapper.get(ldapAttr);
                    UserAttribute attr = new UserAttribute();
                    attr.setName(userAttr);
                    attr.setValue(value);
                }
                user.setAttribute(attributes);
                return user;
            }
            
        }, processor);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#merge(java.lang.Object)
     */
    @Override
    public User merge(User entity) {
        return entity;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#remove(java.lang.Object)
     */
    @Override
    public boolean remove(User entity) {
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#removeById(java.io.Serializable)
     */
    @Override
    public boolean removeById(Long id) {
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#find(java.io.Serializable)
     */
    @Override
    public User find(Long id) {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#save(T[])
     */
    @Override
    public User[] save(User... entities) {
        return entities;
    }

    @Override
    public int count(ISearch search) {
        return search(search).size();
    }

}
