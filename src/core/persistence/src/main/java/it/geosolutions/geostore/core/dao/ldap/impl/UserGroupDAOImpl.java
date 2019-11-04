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
import javax.naming.directory.SearchControls;
import org.apache.log4j.Logger;
import org.springframework.expression.Expression;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DirContextProcessor;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.transaction.annotation.Transactional;
import com.googlecode.genericdao.search.Filter;
import com.googlecode.genericdao.search.ISearch;
import it.geosolutions.geostore.core.dao.UserGroupDAO;
import it.geosolutions.geostore.core.model.UserGroup;
import it.geosolutions.geostore.core.model.enums.GroupReservedNames;

/**
 * Class UserGroupDAOImpl.
 * 
 * @author Tobia di Pisa (tobia.dipisa at geo-solutions.it)
 * @author ETj (etj at geo-solutions.it)
 */
@Transactional(value = "geostoreTransactionManager")
public class UserGroupDAOImpl  extends LdapBaseDAOImpl implements UserGroupDAO {
    
    

    private static final Logger LOGGER = Logger.getLogger(UserGroupDAOImpl.class);

    private boolean addEveryOneGroup = false;
    
    public UserGroupDAOImpl(ContextSource contextSource) {
        super(contextSource);
    }
    
    public boolean isAddEveryOneGroup() {
        return addEveryOneGroup;
    }

    public void setAddEveryOneGroup(boolean addEveryOneGroup) {
        this.addEveryOneGroup = addEveryOneGroup;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#persist(T[])
     */
    @Override
    public void persist(UserGroup... entities) {
        
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#findAll()
     */
    @Override
    public List<UserGroup> findAll() {
        return addEveryOne(ldapSearch(baseFilter, new NullDirContextProcessor()), null);
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#find(java.io.Serializable)
     */
    @Override
    public UserGroup find(Long id) {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#search(com.trg.search.ISearch)
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<UserGroup> search(ISearch search) {
        return addEveryOne(ldapSearch(combineFilters(baseFilter, getLdapFilter(search)), getProcessorForSearch(search)), search.getFilters());
    }

    protected List<UserGroup> ldapSearch(String filter, DirContextProcessor processor) {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return template.search(searchBase, filter, controls, new AbstractContextMapper() {
            int counter = 1;
            @Override
            protected UserGroup doMapFromContext(DirContextOperations ctx) {
                UserGroup group = new UserGroup();
                group.setId((long)counter++);
                group.setEnabled(true);
                group.setGroupName(ctx.getStringAttribute(nameAttribute));
                group.setDescription(ctx.getStringAttribute(descriptionAttribute));
                
                return group;
            }
            
        }, processor);
    }

    private List<UserGroup> addEveryOne(List<UserGroup> groups, List<Filter> filters) {
        UserGroup everyoneGroup = new UserGroup();
        everyoneGroup.setGroupName(GroupReservedNames.EVERYONE.groupName());
        everyoneGroup.setId((long)(groups.size() + 1));
        everyoneGroup.setEnabled(true);
        if (filters == null || matchFilters(everyoneGroup, filters)) {
            boolean everyoneFound = false;
            for (UserGroup group : groups) {
                if (group.getGroupName().equals(everyoneGroup.getGroupName())) {
                    everyoneFound = true;
                }
            }
            if (!everyoneFound && addEveryOneGroup) {
                groups.add(everyoneGroup);
            }
        }
        return groups;
    }

    protected boolean matchFilters(UserGroup group, List<Filter> filters) {
        Expression matchExpression = getSearchExpression(filters);
        return matchExpression.getValue(group, Boolean.class);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#merge(java.lang.Object)
     */
    @Override
    public UserGroup merge(UserGroup entity) {
        return entity;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.trg.dao.jpa.GenericDAOImpl#remove(java.lang.Object)
     */
    @Override
    public boolean remove(UserGroup entity) {
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

    @Override
    public UserGroup[] save(UserGroup... entities) {
        return entities;
    }

    @Override
    public int count(ISearch search) {
        return search(search).size();
    }

}
