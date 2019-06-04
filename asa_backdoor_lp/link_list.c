#include <stdio.h>
#include <stdlib.h>

#include "link_list.h"
#include "asa_func.h"
#include "global.h"

LIST_NODE *alloc_list_node()
{
    LIST_NODE *pNewNode = NULL;

    pNewNode = (LIST_NODE *)asa_malloc(sizeof(LIST_NODE));
    if(pNewNode == NULL)
        return NULL;
    ex_memset((char *)pNewNode, 0x00, sizeof(LIST_NODE));

    return pNewNode;
}

LIST_NODE *create_link_list(void *pElemAddr)
{
    LIST_NODE *pHdr = NULL;

    pHdr = alloc_list_node();
    if(pHdr == NULL)
        return NULL;
    pHdr->p_elem_addr = pElemAddr;

    return pHdr;
}

int destory_link_list(LIST_NODE *pListHdr)
{
    LIST_NODE *pCurrNode = NULL;
    LIST_NODE *pNextNode = NULL;

    if(pListHdr == NULL)
        return -1;

    for(pCurrNode=pListHdr; pCurrNode != NULL;)
    {
        pNextNode = pCurrNode->next;
        asa_free(pCurrNode);
        pCurrNode = pNextNode;
    }

    return 0;
}

int destory_link_list_and_elem(LIST_NODE *pListHdr)
{
    LIST_NODE *pCurrNode = NULL;

    if(pListHdr == NULL)
        return -1;

    for(pCurrNode=pListHdr; pCurrNode != NULL; pCurrNode=pCurrNode->next)
        if(pCurrNode->p_elem_addr != NULL)
            asa_free(pCurrNode->p_elem_addr);
    destory_link_list(pListHdr);

    return 0;
}

LIST_NODE *append_list_node(LIST_NODE *pHdr, void *pElemAddr)
{
    LIST_NODE *pCurrNode = NULL;
    LIST_NODE *pPrevNode = NULL;

    if(pHdr == NULL) return NULL;

    for(pCurrNode=pHdr, pPrevNode=pHdr; pCurrNode->next != NULL; pCurrNode=pCurrNode->next)
        pPrevNode = pCurrNode;

    pCurrNode->next = alloc_list_node();
    if(pCurrNode->next == NULL)
        return NULL;
    pCurrNode->next->prev = pPrevNode;
    pCurrNode->next->p_elem_addr = pElemAddr;

    return pCurrNode->next;
}

LIST_NODE *delete_list_node(LIST_NODE *pNode)
{
    LIST_NODE *pPrevNode = NULL;
    LIST_NODE *pNextNode = NULL;

    if(pNode == NULL) return -1;

    pPrevNode = pNode->prev;
    pNextNode = pNode->next;

    if(pPrevNode == NULL)
    {
        //This node is list header
        if(pNextNode != NULL)
            pNextNode->prev = NULL;
        asa_free(pNode);
    }
    else
    {
        pPrevNode->next = pNextNode;
        if(pNextNode != NULL)
            pNextNode->prev = pPrevNode;
        asa_free(pNode);
    }

    return pNextNode;
}

LIST_NODE *delete_list_node_and_elem(LIST_NODE *pNode)
{
    if(pNode == NULL)
        return NULL;
    if(pNode->p_elem_addr != NULL)
        asa_free(pNode->p_elem_addr);
    return delete_list_node(pNode);
}

int traversal_link_list(LIST_NODE *pHdr, int(*callback_handler)(LIST_NODE *, void *), void *param)
{
    LIST_NODE *pCurrNode = NULL;

    if(pHdr == NULL || callback_handler == NULL)
        return -1;

    for(pCurrNode=pHdr; pCurrNode != NULL; pCurrNode=pCurrNode->next)
        if(callback_handler(pCurrNode, param) == 0) //callback函数返回0则退出遍历
            break;

    return 0;
}




