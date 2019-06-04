#ifndef LINK_LIST_H_INCLUDED
#define LINK_LIST_H_INCLUDED

typedef struct _Link_List_Node_
{
    void *p_elem_addr;
    struct _Link_List_Node_ *prev;
    struct _Link_List_Node_ *next;
}LIST_NODE;

/////////////////////////////////////////////////////////////////
LIST_NODE *create_link_list(void *pElemAddr);
int destory_link_list(LIST_NODE *pListHdr);
int destory_link_list_and_elem(LIST_NODE *pListHdr);
LIST_NODE *append_list_node(LIST_NODE *pHdr, void *pElemAddr);
LIST_NODE *delete_list_node(LIST_NODE *pNode);
LIST_NODE *delete_list_node_and_elem(LIST_NODE *pNode);
int traversal_link_list(LIST_NODE *pHdr, int(*callback_handler)(LIST_NODE *, void *), void *param);

#endif // LINK_LIST_H_INCLUDED
